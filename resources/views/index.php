<html>
    <head>
      <title>Apple Lumen</title>
      <script type="text/javascript" src="https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js"></script>
    </head>
    <body>
        <h1>Hello,Lumen</h1>
        <div id="appleid-signin" data-color="black" data-border="true" data-type="sign in"></div>
        <script>
          AppleID.auth.init({
            clientId : '<?php echo $client_id ?>',
            redirectURI : '<?php echo $redirect_uri ?>',
            state : '<?php echo $state ?>'
          });
        </script>
    </body>
</html>
