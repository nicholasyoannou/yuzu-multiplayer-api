<h1 align="left">
Yuzu Multiplayer API
</h1>
<p align="left">
An API built for Yuzu's multiplayer system, built to support token authentication (so users can sign up, login, etc with custom implementation), and the popular rooms system.
</p>

This is built in FastAPI, a Python framework. This may not be built to fit production but has been tested with a Yuzu fork (as of 10/03/2024) and can confirm this to be fully working. This does require Yuzu to be rebuilt (to change the API URL), and the API URL to be changed in common, settings.h.

This is built as more as a draft, so there could be things that are missing, or overlooked things that could be a security muckup. Licensing is GNU, so free use to modify, publish, redistribute, etc. However, if used in your own projects, please give credit where credit is due, thank you.

## Usage and how to use
There are 2 keys which'll need to be generated: a public and private key. This is used for JWT for use in Yuzu, for token authentication. This can be done with two simple commands (using openssl):

- openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
- openssl rsa -pubout -in private_key.pem -out public_key.pem
