import logo from './logo.svg';
import './App.css';
import { Route,Routes } from 'react-router-dom';
import { FileUpload } from './pages/FileUpload.js'

function App() {


  return <Route>
    <Route path='/'>{<FileUpload />}</Route>
  </Route>
}

export default App;
