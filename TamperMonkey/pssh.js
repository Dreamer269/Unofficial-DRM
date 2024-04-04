// ==UserScript==
// @name         extractPSSH
// @namespace    http://your.namespace.com
// @version      1.0
// @description  Extract PSSH data from MediaKeySession generateRequest method
// @author       Your Name
// @match        *://*/*
// @grant        none
// ==/UserScript==

(async () => {
    const b64 = {
        decode: s => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
        encode: b => btoa(String.fromCharCode(...new Uint8Array(b)))
    };

    const extractPSSH = (initData) => {
        const pssh = b64.encode(initData);
        console.groupCollapsed(
            `PSSH: ${pssh}`
        );
        console.trace();
        console.groupEnd();
        // Do something with pssh data if needed
    };

    // Intercept MediaKeySession generateRequest method
    const originalGenerateRequest = MediaKeySession.prototype.generateRequest;
    MediaKeySession.prototype.generateRequest = async function (...args) {
        const [initDataType, initData] = args;
        extractPSSH(initData);
        // Call the original generateRequest method
        return originalGenerateRequest.apply(this, args);
    };
})();
