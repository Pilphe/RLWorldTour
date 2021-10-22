# RLWorldTour

mitmproxy Python addon which allows registering to all Rocket League tournaments of the world without restrictions.

To be able to use this script you must reverse and patch/hook Rocket League executable file to disable certificate verifications and find secrets to generate requests signatures, I `<removed>` them but here's a [hint](https://github.com/AeonLucid/RocketLeaguePublic).

Then to be able to send Rocket League traffic through mitmproxy I used [Proxifier](https://www.proxifier.com/).

You can also edit this script to be able to edit any HTTPS/WebSocket traffic between you and the game (like the config file for example).

It also drops all metrics requests.

![](https://i.imgur.com/0XxxvtH.gif)