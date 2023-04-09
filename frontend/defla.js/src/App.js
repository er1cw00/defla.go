import React, { Component } from 'react';
import ReactDOM from 'react-dom/client';
import logo from './logo.svg';
import './App.css';
import Workspace from './pages/Workspace'

class App extends React.Component {
  render() {
    return (
      <div className="App">

          <Workspace />

      </div>
    );
  }
}

export default App;
