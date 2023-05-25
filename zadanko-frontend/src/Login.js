import React, { useState } from "react";
import axios from "axios";
import { NavLink } from 'react-router-dom';

const Login = () => {
  const [loginInput, setLoginInput] = useState({
    email: "",
    password: "",
  });

  const handleInputChange = (event) => {
    setLoginInput({
      ...loginInput,
      [event.target.name]: event.target.value,
    });
  };

  const login = async () => {
    try {
      await axios.post("http://localhost:3000/login", loginInput);
      window.location = "/dashboard";
    } catch (error) {
      alert("Nie udało się zalogować");
    }
  };

  return (
    <div className="home">
      <div className="login-container">
        <h2 className="login-header">Logowanie</h2>
        <form className="login-form">
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
        <button onClick={login} className="login-button">Zaloguj</button>
        <div className="login-buttons">
          <span><NavLink to="/">Główne menu</NavLink></span>
          <span><NavLink to="/register">Zarejestruj</NavLink></span>
        </div>
      </div>
    </div>
  );
};

export default Login;
