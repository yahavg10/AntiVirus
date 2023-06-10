
//drag and drop file button?
// dragover and dragenter events need to have 'preventDefault' called
// in order for the 'drop' event to register. 
// See: https://developer.mozilla.org/en-US/docs/Web/Guide/HTML/Drag_operations#droptargets
dropContainer.ondragover = dropContainer.ondragenter = function(evt) {
  evt.preventDefault();
};

dropContainer.ondrop = function(evt) {
  // pretty simple -- but not for IE :(
  fileInput.files = evt.dataTransfer.files;

  // If you want to use some of the dropped files
  const dT = new DataTransfer();
  dT.items.add(evt.dataTransfer.files[0]);
  dT.items.add(evt.dataTransfer.files[3]);
  fileInput.files = dT.files;

  evt.preventDefault();
};

{
<html>
<body>
<div id="dropContainer" style="border:1px solid black;height:100px;">
   Drop Here
</div>
  <form action="">
  <input type="file" id="myFile" name="filename">
  <input type="submit">
</form>
</body>
</html>

}


//create button to get file from user personal computer in react?
import React, { useRef } from 'react'

const MyComponent = () => {
  const ref = useRef()
  const handleClick = (e) => {
    ref.current.click()
  }
  return (
    <>
      <button onClick={handleClick}>Upload file</button>
      <input ref={ref} type="file" />
    </>
  )
}



//how to Create login page in react?
    fetch(this.email.value, this.password.value)
    .then(res => {
        localStorage.setItem('id_token', res.token) // Store token 
    })
    .catch(err => {
        console.log(err);
    });


    class AuthService{
        login(email, password) {
            return this.fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email, 
                    password
                })
            })
              .then(res => {
                if(res.type == 'success'){
                    this.setToken(res.token) // Setting the token in localStorage
                    return Promise.resolve(res); 
                } else {
                    return Promise.reject(res)
                }
            })
        }


  // Other available methods
       setToken(idToken) {
        // Saves user token to localStorage
        localStorage.setItem('id_token', idToken)
       }

      getProfile() {
        // Using jwt-decode npm package to decode the token
        return decode(localStorage.getItem('id_token')); // assuming you have jwt token then use jwt-decode library
      }
    }


import AuthUtility from './utils/AuthUtility';

login = (e) => {


    this.Auth.login(this.email.value, this.password.value)
    .then(res => {
        this.props.history.push('/protectedRoute');
    })
    .catch(err => {
        console.log(error);
    });
}



