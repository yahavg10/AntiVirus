function verificateMD5()
{
  var input = document.getElementById("myFile");
  var reader = new FileReader();
  reader.readAsBinaryString(file)
  reader.onload = function(event) {
    var binary = event.target.result;
    var md5 = CryptoJS.MD5(binary).toString();
	var xhr = new XMLHttpRequest();
	xhr.open('POST','/VerifyMD5.api');
	xhr.send("md5="+md5);
  };
  
  http.onreadystatechange = function() {//Call a function when the state changes.
    if(http.readyState == 4 && http.status == 200) {
        alert(http.responseText);
    }
  
};
}

