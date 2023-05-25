const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const PORT = 3000;
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'rekrutacja'
});

app.get('/', (req, res) => {
  res.send('Witaj w mojej aplikacji!');
});

app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}.`);
});

db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('Połączono z bazą danych.');
});

app.post('/register', (req, res) => {
    const { name, surname, email, password } = req.body;

    if (!name || !surname || !email || !password || password.length < 8) {
        res.status(400).send('Nieprawidłowe dane wejściowe');
        return;
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            res.status(500).send('Wystąpił błąd podczas przetwarzania danych');
        } else if (result.length > 0) {
            res.status(400).send('Użytkownik o podanym adresie email już istnieje');
        } else {
            bcrypt.hash(password, saltRounds, (err, hash) => {
                if (err) {
                    res.status(500).send('Wystąpił błąd podczas hashowania hasła');
                } else {
                    db.query(
                        'INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)',
                        [name, surname, email, hash],
                        (err, result) => {
                            if (err) {
                                res.status(500).send('Wystąpił błąd podczas rejestracji');
                            } else {
                                res.send('Pomyślna rejestracja');
                            }
                        }
                    );
                }
            });
        }
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(400).send('Nieprawidłowe dane wejściowe');
        return;
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
        if (err) {
            res.status(500).send('Wystąpił błąd podczas przetwarzania danych');
        } else if (users.length > 0) {
            const user = users[0];

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    res.status(500).send('Wystąpił błąd podczas porównywania haseł');
                } else if (result) {
                    res.send('Zalogowano pomyślnie');
                } else {
                    res.status(401).send('Nieprawidłowe hasło');
                }
            });
        } else {
            res.status(404).send('Nie znaleziono użytkownika');
        }
    });
});
