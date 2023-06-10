//get a Base refrence of the dataBase
var ref = firebase.database().ref();
//creating an instance of the needed functions
var myFuncs = {email: GetEmailByUserName(), name : GetName(), password : GetPasswordByUserName()};
window[myFuncs];

//check if Md5hash Already exist in FireBase
ref.child("Files").orderByChild("ID").equalTo(filemd5).once("value",snapshot => {
    if (snapshot.exists()){
      console.log("exists!", userData);
    }
    else{
        //send an OK message to client allowing client to show an Upload btn.
    }
});

//check if user Already exist in FireBase
ref.child("users").orderByChild("ID").equalTo(myFuncs[email]()).once("value",snapshot => {
  if (snapshot.exists()){
    const userData = snapshot.val();
    console.log("exists!", userData);
  }
});




