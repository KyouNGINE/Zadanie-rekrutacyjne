import React, { useState } from "react";
import axios from "axios";
import { NavLink } from "react-router-dom";

const Register = () => {
  const [registerInput, setRegisterInput] = useState({
    name: "",
    surname: "",
    email: "",
    password: "",
  });

  const handleInputChange = (event) => {
    setRegisterInput({
      ...registerInput,
      [event.target.name]: event.target.value,
    });
  };

  const register = async () => {
    try {
      await axios.post("http://localhost:3000/register", registerInput);
      window.location = "/login";
    } catch (error) {
      alert("Nie udało się zarejestrować");
    }
  };

  return (
    <div className="home">
      <div className="register-home">
        <h2 className="register-header">Rejestracja</h2>
        <form className="register-form">
          <input
            type="text"
            name="name"
            placeholder="Imię"
            onChange={handleInputChange}
          />
          <input
            type="text"
            name="surname"
            placeholder="Nazwisko"
            onChange={handleInputChange}
          />
          <input
            type="email"
            name="email"
            placeholder="Email"
            onChange={handleInputChange}
          />
          <input
            type="password"
            name="password"
            placeholder="Hasło"
            onChange={handleInputChange}
          />
        </form>
        <button onClick={register} className="register-button">Zarejestruj</button>
        <div className="register-buttons">
          <span><NavLink to="/">Główne menu</NavLink></span>
          <span><NavLink to="/login">Zaloguj</NavLink></span>
        </div>
      </div>
    </div>
  );
};

export default Register;
