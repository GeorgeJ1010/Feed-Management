
var onSignIn=(googleUser)=> {

/*	var profile = googleUser.getBasicProfile()
	console.log('ID: ' + profile.getId())
	console.log('Name: ' + profile.getName())
	console.log('Image URL: ' + profile.getImageUrl())
  	console.log('Email: ' + profile.getEmail())
*/
	var id_token = googleUser.getAuthResponse().id_token
	var xhr = new XMLHttpRequest()
	xhr.open("POST", "/google", true)
    xhr.setRequestHeader('Content-Type', 'application/json')
    var obj={"idtoken":id_token};
    xhr.send(JSON.stringify(obj))
    xhr.onload = function() {
	  var data = JSON.parse(this.responseText)
	  if(data["success"]==true)
		{
			window.location.href = "/"
		}
	  else
		{
			throwError(data)
		}
    }
	
}
      
var userLogin=()=>{
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/login", true);
	xhr.setRequestHeader('Content-Type', 'application/json');
	var email=document.getElementById("email").value;
	var pass=document.getElementById("password").value;
 	if(validate(email,pass)){
		var obj={"email":email,"password":pass};
		xhr.send(JSON.stringify(obj));
		xhr.onload = function() {
		  var data = JSON.parse(this.responseText);
		  if(data["success"]==true)
			{

				window.location.href = "/";
			}
		  else
			{
				throwError(data);
			}
		  
		}
	}
}

/*
var userRegister=()=>{
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/register", true);
	xhr.setRequestHeader('Content-Type', 'application/json');
	var email=document.getElementById("email").value;
	var pass=document.getElementById("password").value;

 	if(validate(email,pass)){
		var obj={"email":email,"password":pass};
		xhr.send(JSON.stringify(obj));
		xhr.onload = function() 
		{
			var data=JSON.parse(this.responseText);
		    if(data["success"]==true)
			{

				window.location.href = "/login";
	
			}
			 else
			{
				throwError(data);
			}
		}
	}

}


*/

var userRegister=()=>{
		var xhr = new XMLHttpRequest();

	xhr.open("POST", "https://georgefulltraining12.uc.r.appspot.com/register", true);
	xhr.setRequestHeader('Content-Type', 'application/json');
	var email=document.getElementById("email").value;
	var pass=document.getElementById("password").value;
    xhr.setRequestHeader("Accept","application/json");

 	if(validate(email,pass)){
		var obj={"email":email,"password":pass};
		xhr.send(JSON.stringify(obj));
		xhr.onload = function() 
		{
			var data=JSON.parse(this.responseText);
		    if(data["success"]==true)
			{

				window.location.href = "/login";
	
			}
			 else
			{
				throwError(data);
			}
		}
	}

}



var logout=()=>{
    var auth2 = gapi.auth2.getAuthInstance();
    auth2.signOut().then(function () {
    console.log('User signed out.');
    });
	var cacheName="getFeeds"
	let url = '/feed';
	caches.open(cacheName).then(cache => {
		cache.delete(url+"/trash")
	})
	var xhr = new XMLHttpRequest();
	xhr.open("GET", "/logout", true);
	xhr.setRequestHeader('Content-Type', 'application/json');
	xhr.send();
	xhr.onload= function (){
		var data=JSON.parse(this.responseText);
		if(data["success"]==true)
		{

			window.location.href = "/login";

		}
	
		
	};

}




var validate=(email,pass)=>{
	var mailformat = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
	var passw=  /^(?=\D*\d)(?=[^a-z]*[a-z])[\w~@#$%^&*+=`|{}:;!.?\"()\[\]-]{8,25}$/;

	if(email=="" || pass=="")
	{
		var e=document.getElementById("blank");
		e.style.display="block";
		return false;
		
	}
	else if(!email.match(mailformat))
	{
		var e=document.getElementById("wrong");
		e.style.display="block";
		return false;
	}
	else if(!pass.match(passw))
	{
		var e=document.getElementById("wrongP");
		e.style.display="block";
		return false;
	}


	return true;
}


var throwError=(data)=>{
		var e=document.getElementById("dbError");
		e.innerHTML=data["message"];
		e.style.display="block";
}



var errorToggle=()=>{
			document.getElementById("blank").style.display="none";
			document.getElementById("wrong").style.display="none";
			document.getElementById("wrongP").style.display="none";
			document.getElementById("dbError").style.display="none";
}




