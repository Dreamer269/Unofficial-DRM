// ==UserScript==
// @name         Fake Widevine
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  Fake the presence of a functional Widevine CDM - enough to get the spotify UI to launch, so you can pick another playback device.
// @author       David Buchanan
// @match        https://open.spotify.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=spotify.com
// @grant        none
// ==/UserScript==

(window => {
    'use strict';

    function MediaKeySession() {
        this.sessionId = "";
    }

    function MediaKeys() {
        this.autoId = "MediaKeys_1";
    };

    MediaKeys.prototype.createSession = () => {
        return new Promise((resolve, reject) => {
            resolve(new MediaKeySession());
        });
    };

    function MediaKeySystemAccess(config) {
        this.name = "com.widevine.alpha";
        this.keySystem = "com.widevine.alpha";
        this.autoId = "MediaKeySystemAccess_1";
        this.config = config;
    };

    MediaKeySystemAccess.prototype.createMediaKeys = () => {
        //console.log("it's happening!");
        return new Promise((resolve, reject) => {
            resolve(new MediaKeys());
        });
    };

    MediaKeySystemAccess.prototype.getConfiguration = () => {
        return new Promise((resolve, reject) => {
            resolve(this.config);
        });
    };

    window.navigator.requestMediaKeySystemAccess = (keySystem, supportedConfigurations) => {
        //console.log("hooked!");
        return new Promise((resolve, reject) => {
            if (keySystem !== "com.widevine.alpha") {
                reject("Unsupported keySystem or supportedConfiguration");
            }
            resolve(new MediaKeySystemAccess(supportedConfigurations));
        });
    };
})(window);
