<!DOCTYPE html>
<html lang="en">

  <head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Magicka BBS</title>

    <!-- Bootstrap core CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
    <link rel="stylesheet" media="(max-width: 767px)" href="@@WWW_URL@@static/style-mobile.css">
    <link rel="stylesheet" media="(min-width: 768px)" href="@@WWW_URL@@static/style.css">
    <!-- Custom styles for this template -->
    <style>
      body {
        padding-top: 84px;
      }
      @media (min-width: 992px) {
        body {
          padding-top: 86px;
        }
      }
    </style>
	<script language='javascript'>
		function validate () {
			if(document.getElementById('recipient').value=="") {
				alert("To can not be empty.");
				return false;
			}
			if(document.getElementById('subject').value=="") {
				alert("Subject can not be empty");
				return false;
			}
			if(document.getElementById('body').value=="") {
				alert("Can't send an empty message!");
				return false;
			}
			return true;
		}
	</script>	
  </head>

  <body>

    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
      <div class="container">
        <a class="navbar-brand" href="@@WWW_URL@@">
        <picture>
			    <source srcset="@@WWW_URL@@static/header-m.png" media="(max-width: 767px)">
			    <source srcset="@@WWW_URL@@static/header.png">
			    <img src="@@WWW_URL@@static/header.png" alt="Magicka BBS" />
		    </picture>	

        </a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarResponsive">
          <ul class="navbar-nav ml-auto">
            <li class="nav-item">
              <a class="nav-link" href="@@WWW_URL@@">Home</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="@@WWW_URL@@blog/">News</a>
            </li>            
            <li class="nav-item">
              <a class="nav-link" href="@@WWW_URL@@last10/">Last 10 Callers</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="@@WWW_URL@@email/">Email</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="@@WWW_URL@@msgs/">Conferences</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="@@WWW_URL@@files/areas/">File Areas</a>
            </li>            
          </ul>
        </div>
      </div>
    </nav>
    <!-- Page Content -->
    <div class="container">
      <div class="row">
        <div class="col-lg-12">
