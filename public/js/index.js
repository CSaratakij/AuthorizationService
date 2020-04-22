//Don't forget to obfuscated when deploy
let params;

window.addEventListener("load", (e) => {
    let loginForm = document.getElementById("form-login");
    params = (new URL(document.location)).searchParams;

    if (loginForm) {
        loginForm.onsubmit = (e) => {
            login(e);
        }
    }

    let registerForm = document.getElementById("form-register");

    if (registerForm) {
        registerForm.onsubmit = (e) => {
            signup(e);
        }
    }

    let btnVerify = document.getElementById("btnVerify");

    if (btnVerify) {
        btnVerify.onclick = (e) => {
            sendNewVerifyEmail(e);
        }
    }
});

async function postData(url = '', data = {}) {
    const response = await fetch(url, {
        method: 'POST',
        mode: 'same-origin',
        cache: 'no-cache',
        headers: {
        'Content-Type': 'application/json'
        },
        redirect: 'manual',
        referrerPolicy: 'no-referrer',
        body: JSON.stringify(data)
    });
    return response;
}

async function login(e) {
    e.preventDefault();

    let username = document.getElementById("username");
    let password = document.getElementById("password");
    let ckbRememberMe = document.getElementById("ckb-remember-me");

    let state = params.get("state");
    let redirect_uri = params.get("redirect_uri");
    let code_challenge = params.get("code_challenge");
    let code_challenge_method = params.get("code_challenge_method");

    let data = {
        username: username.value,
        password: sha256(password.value),
        state: state,
        redirect_uri: redirect_uri,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method,
    }

    try {
        await postData('/auth', data)
        .then((res) => {
            if (res.status != 200)
                throw "error";

            res.json().then(data => {
                let url = data.redirect_uri + "?code=" + data.code + "&state=" + data.state;

                if (ckbRememberMe.checked) {
                    url += "&remember_me=true"
                }

                // window.location.href = url
                window.location.replace(url);
            });
        });
    }
    catch (err) {
        console.log(err);
        //tell user that u fuckup your credential
    }
}

async function signup(e) {
    e.preventDefault();

    let fullname = document.getElementById("full-name");
    let username = document.getElementById("your-email");
    let password = document.getElementById("password");

    let data = {
        username: username.value,
        fullname: fullname.value,
        password: sha256(password.value)
    }

    await postData('/signup', data)
    .then((res) => {
        if (res.status != 201) {
            throw "error";
        }

        alert("Register completed...(check your email)");
        //replace by sweetalert, and provide a link for re-send verification email
    })
    .catch(err => {
        alert("Cannot signup...");
        //replace by sweetalert, alert that account is exists
    });
}

async function sendNewVerifyEmail(e) {
    let username = document.getElementById("your-email");

    await postData('/user/verify/new', {
        username: username.value
    })
    .then((res) => {
        if (res.status !== 200)
            throw "error";
        alert("Check your email....");
    }).catch(err => {
        alert("Try again later..");
    });
}

