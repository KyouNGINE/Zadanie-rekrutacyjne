import React from "react";
import { NavLink } from "react-router-dom";

const Dashboard = () => {
  const user = JSON.parse(localStorage.getItem('user'));

  return (
    <div className="home">
      <h2 className="dashboard-home">Witaj, {user ? `${user.name} ${user.surname}` : 'Gość'}!</h2>
      <div className="logout"><span><NavLink to="/">Wyloguj</NavLink></span></div>
    </div>
  );
};

export default Dashboard;
