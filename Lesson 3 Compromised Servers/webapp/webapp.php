<!DOCTYPE html>
<html lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Serverlessconf Workshop - Amazing Web App</title>
        <meta name="theme-color" content="#ffffff">
        <link rel="stylesheet" href="./theme.css">
    </head>
    <body>
        <div id="wrapper">
            <main>
                <div class="banner banner-home">
                    <div class="container">
                        <div class="inner-content">
                            <div class="shape-01"><img src="./images/bg-paint01.png" alt=""></div>
                            <div class="clearfix">
                                <a href="http://acloud.guru/" class="logo-cloud"><img src="./images/logo-cloud_guru.png" alt="a cloud guru"></a>
                            </div>
                            <div class="logo-serv_conf">
                                <img src="./images/logo-serverless_conf.png" class="hidden-xs">
                                <img src="./images/logo-serverless_conf-sm.png" class="visible-xs">
                            </div>
                            <div class="info">IPs :: <?php $int=file_get_contents('http://169.254.169.254/latest/meta-data/local-ipv4'); echo $int; echo ' -- ';$ext=file_get_contents('http://169.254.169.254/latest/meta-data/public-ipv4');echo $ext  ?></div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
        <script src="./theme.js"></script>
    </body>
</html>
