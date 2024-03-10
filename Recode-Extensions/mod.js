(async () => {
    const b64 = {
        decode: s => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
        encode: b => btoa(String.fromCharCode(...new Uint8Array(b)))
    };

    const fnproxy = (object, func) => new Proxy(object, { apply: func });

    const proxy = (object, key, func) => Object.defineProperty(object, key, {
        value: fnproxy(object[key], func)
    });
    
    proxy(MediaKeySession.prototype, 'generateRequest', async (_target, _this, _args) => {
        const [initDataType, initData] = _args;
        const pssh = b64.encode(initData);
        console.groupCollapsed(
            `PSSH: ${b64.encode(initData)}`
        );
        console.trace();
        console.groupEnd();
        
        // Retrieve MPD URL, trying all in one (park)
        const mpdLinkElement = document.querySelector('link[rel="manifest"]');
        const mpdUrl = mpdLinkElement ? mpdLinkElement.href : '';
        console.log(`MPD URL: ${mpdUrl}`);
        
        if (pssh)
            window.postMessage({ type: "38405bbb-36ef-454d-8b32-346f9564c978", log: { pssh, mpdUrl } }, "*");
            
        return _target.apply(_this, _args);
    });
})();
