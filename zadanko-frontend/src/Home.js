import React from "react";
import { NavLink } from 'react-router-dom';

const Home = () => {
  return (
    <div className="home">
      <h2 className="home-page">Witaj na stronie głównej!</h2>
      <div className="main-buttons">
        <span><NavLink to="/register">Rejestracja</NavLink></span>
        <span><NavLink to="/login">Logowanie</NavLink></span>
      </div>
    </div>
  );
};

export default Home;
