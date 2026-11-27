// ==UserScript==
// @name         Castle V3 Telemetry Injector
// @namespace    https://castle-deobfuscator.local/
// @version      1.0.0
// @description  Stealth browser telemetry spoofer for Castle Anti-Bot V3
// @match        https://x.com/*
// @match        https://twitter.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
    'use strict';

    // Cấu hình môi trường giả lập
    const CONFIG = {
        // IP Proxy mong muốn (để khớp với outgoing HTTP IP, chống lộ WebRTC STUN)
        proxyIp: '142.250.190.46',

        // Cấu hình GPU phần cứng thật
        gpuVendor: 'Google Inc. (NVIDIA)',
        gpuRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',

        // Cấu hình CPU & RAM
        hardwareConcurrency: 8,
        deviceMemory: 8,

        // Cấu hình Hệ thống & Platform
        platform: 'Win32',
        osName: 'Windows',
        osVersion: '10.0',
        userAgent: navigator.userAgent.replace(/HeadlessChrome/gi, 'Chrome'),

        // Debug logger (bật true nếu muốn xem log trong Console)
        debug: true
    };

    const log = (...args) => {
        if (CONFIG.debug) console.log('[Castle-Injector]', ...args);
    };

    // =========================================================================
    // 0. BẢO VỆ PROTOTYPE toString (Chống phát hiện Monkey-Patching / Hooking)
    // =========================================================================
    const originalToString = Function.prototype.toString;
    const hookedFunctions = new WeakSet();

    function makeNative(fn, name) {
        hookedFunctions.add(fn);
        try {
            Object.defineProperty(fn, 'name', { value: name || fn.name, configurable: true });
        } catch (_) {}
        return fn;
    }

    Function.prototype.toString = function () {
        if (hookedFunctions.has(this)) {
            return `function ${this.name || ''}() { [native code] }`;
        }
        return originalToString.call(this);
    };
    makeNative(Function.prototype.toString, 'toString');

    // =========================================================================
    // 1. [P0] TRIỆT TIÊU AUTOMATION & BOT PROBES
    // =========================================================================

    // 1.1 Xóa bỏ navigator.webdriver (V3 metric [43])
    try {
        const navProto = Object.getPrototypeOf(navigator);
        delete navProto.webdriver;
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
            configurable: true,
            enumerable: true
        });
    } catch (_) {}

    // 1.2 Dọn dẹp biến do Selenium ChromeDriver cấy vào (V3 metric [506] - selenium_cdc)
    const cleanCdcAttributes = () => {
        try {
            const props = Object.getOwnPropertyNames(window.document);
            for (let i = 0; i < props.length; i++) {
                const prop = props[i];
                if (prop.includes('$cdc_') || prop.startsWith('cdc_')) {
                    delete window.document[prop];
                }
            }
        } catch (_) {}
    };
    cleanCdcAttributes();
    window.addEventListener('DOMContentLoaded', cleanCdcAttributes);

    // 1.3 Giả lập window.chrome hoàn chỉnh chống CDP & Headless Probe (V3 metric [355], [445])
    if (!window.chrome) {
        window.chrome = {};
    }
    window.chrome.app = {
        isInstalled: false,
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
    };
    window.chrome.runtime = {
        OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' },
        PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformNaclArch: { ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformOs: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' }
    };
    window.chrome.loadTimes = makeNative(function () {
        return {
            commitLoadTime: Date.now() / 1000 - 0.5,
            connectionInfo: 'h2',
            finishDocumentLoadTime: Date.now() / 1000 - 0.2,
            finishLoadTime: Date.now() / 1000 - 0.1,
            firstPaintAfterLoadTime: 0,
            firstPaintTime: Date.now() / 1000 - 0.4,
            navigationType: 'Other',
            npnNegotiatedProtocol: 'h2',
            requestTime: Date.now() / 1000 - 0.8,
            startLoadTime: Date.now() / 1000 - 0.8,
            wasAlternateProtocolAvailable: false,
            wasFetchedViaSpdy: true,
            wasNpnNegotiated: true
        };
    }, 'loadTimes');
    window.chrome.csi = makeNative(function () {
        return {
            onloadT: Date.now(),
            startE: Date.now() - 500,
            pageT: 500,
            tran: 15
        };
    }, 'csi');

    // 1.4 Giả lập Permissions API (Notification permission 'default')
    if (navigator.permissions && navigator.permissions.query) {
        const origQuery = navigator.permissions.query;
        navigator.permissions.query = makeNative(function (parameters) {
            if (parameters && parameters.name === 'notifications') {
                return Promise.resolve({
                    state: Notification.permission,
                    onchange: null
                });
            }
            return origQuery.apply(this, arguments);
        }, 'query');
    }

    // 1.5 Plugins & MimeTypes (Tránh rỗng của môi trường headless)
    if (!navigator.plugins || navigator.plugins.length === 0) {
        const mockPlugins = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }
        ];
        Object.defineProperty(navigator, 'plugins', {
            get: () => mockPlugins,
            configurable: true
        });
    }

    // =========================================================================
    // 2. [P0] WEBRTC IP SPOOFING & LEAK PREVENTION (V3 metric [212] - client_ip)
    // =========================================================================
    if (window.RTCPeerConnection && CONFIG.proxyIp) {
        const OriginalRTCPeerConnection = window.RTCPeerConnection;
        window.RTCPeerConnection = makeNative(function (rtcConfig) {
            const pc = new OriginalRTCPeerConnection(rtcConfig);

            const originalAddEventListener = pc.addEventListener;
            pc.addEventListener = makeNative(function (type, listener, options) {
                if (type === 'icecandidate') {
                    const wrappedListener = function (event) {
                        if (event && event.candidate && event.candidate.candidate) {
                            const candidateStr = event.candidate.candidate;
                            const modified = candidateStr.replace(
                                /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
                                CONFIG.proxyIp
                            );
                            try {
                                Object.defineProperty(event.candidate, 'candidate', {
                                    value: modified,
                                    configurable: true
                                });
                                Object.defineProperty(event.candidate, 'address', {
                                    value: CONFIG.proxyIp,
                                    configurable: true
                                });
                            } catch (_) {}
                        }
                        return listener.apply(this, arguments);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                }
                return originalAddEventListener.apply(this, arguments);
            }, 'addEventListener');

            return pc;
        }, 'RTCPeerConnection');
        window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
    }

    // =========================================================================
    // 3. [P1] HARDWARE FINGERPRINTING SPOOFER (WebGL, Canvas, Audio, CPU, RAM)
    // =========================================================================

    // 3.1 Hardware Concurrency & Device Memory (V3 metric [85], [668])
    Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: () => CONFIG.hardwareConcurrency,
        configurable: true
    });
    Object.defineProperty(navigator, 'deviceMemory', {
        get: () => CONFIG.deviceMemory,
        configurable: true
    });
    Object.defineProperty(navigator, 'platform', {
        get: () => CONFIG.platform,
        configurable: true
    });

    // 3.2 WebGL GPU Renderer & Vendor (V3 metric [237], [573])
    const hookWebGL = (proto) => {
        if (!proto) return;
        const origGetParameter = proto.getParameter;
        proto.getParameter = makeNative(function (param) {
            // UNMASKED_VENDOR_WEBGL = 0x9245
            if (param === 0x9245 || param === 37445) {
                return CONFIG.gpuVendor;
            }
            // UNMASKED_RENDERER_WEBGL = 0x9246
            if (param === 0x9246 || param === 37446) {
                return CONFIG.gpuRenderer;
            }
            // VENDOR = 0x1F00
            if (param === 0x1F00 || param === 7936) {
                return 'WebKit';
            }
            // RENDERER = 0x1F01
            if (param === 0x1F01 || param === 7937) {
                return 'WebKit WebGL';
            }
            return origGetParameter.apply(this, arguments);
        }, 'getParameter');
    };

    if (window.WebGLRenderingContext) hookWebGL(WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) hookWebGL(WebGL2RenderingContext.prototype);

    // 3.3 Canvas 2D Hash Noise Generator (V3 metric [10] - canvas_fp)
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = makeNative(function () {
        const ctx = this.getContext('2d');
        if (ctx && this.width > 0 && this.height > 0) {
            try {
                const imgData = ctx.getImageData(0, 0, 1, 1);
                imgData.data[3] = Math.max(1, imgData.data[3] ^ 1);
                ctx.putImageData(imgData, 0, 0);
            } catch (_) {}
        }
        return origToDataURL.apply(this, arguments);
    }, 'toDataURL');

    // 3.4 AudioContext Fingerprint Micro-Jitter (V3 metric [179] - audio_fp)
    if (window.AudioBuffer) {
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = makeNative(function () {
            const data = origGetChannelData.apply(this, arguments);
            for (let i = 0; i < Math.min(data.length, 10); i++) {
                data[i] += 0.000000001 * (i % 2 === 0 ? 1 : -1);
            }
            return data;
        }, 'getChannelData');
    }

    // =========================================================================
    // 4. [P2] DYNAMICS, TIMING JITTER & SIMULATED USER INTERACTION
    // =========================================================================

    // 4.1 Tạo dao động thời gian thực tế (Hardware Jitter) cho requestAnimationFrame
    const origRAF = window.requestAnimationFrame;
    window.requestAnimationFrame = makeNative(function (callback) {
        return origRAF.call(window, function (timestamp) {
            const jitter = (Math.random() - 0.5) * 0.05;
            return callback(timestamp + jitter);
        });
    }, 'requestAnimationFrame');

    // 4.2 Tự động phát sinh tương tác người dùng hợp lệ trước khi Castle kiểm tra
    const simulateInitialUserEvent = () => {
        try {
            const target = document.body || document.documentElement;
            if (!target) return;

            const x = Math.floor(100 + Math.random() * 500);
            const y = Math.floor(100 + Math.random() * 300);

            const moveEvent = new MouseEvent('pointermove', {
                clientX: x,
                clientY: y,
                screenX: x + 50,
                screenY: y + 100,
                bubbles: true,
                cancelable: true,
                view: window
            });
            target.dispatchEvent(moveEvent);

            const focusEvent = new FocusEvent('focus', {
                bubbles: false,
                cancelable: false,
                view: window
            });
            window.dispatchEvent(focusEvent);

            log('Đã tạo sự kiện tương tác giả lập người dùng hợp lệ.');
        } catch (e) {
            log('simulateInitialUserEvent error:', e);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', simulateInitialUserEvent);
    } else {
        setTimeout(simulateInitialUserEvent, 50);
    }

    // =========================================================================
    // 5. [HOOK] TỰ ĐỘNG BẮT (CAPTURE) TOKEN KHI CASTLE TẠO RA
    // =========================================================================
    window.__CASTLE_TOKENS = [];

    window.__getLastCastleToken = () => {
        return window.__CASTLE_TOKENS.length > 0
            ? window.__CASTLE_TOKENS[window.__CASTLE_TOKENS.length - 1]
            : null;
    };

    const hookCastleInstance = (inst) => {
        if (!inst || inst.__is_hooked) return;
        inst.__is_hooked = true;

        if (typeof inst.createRequestToken === 'function') {
            const origCreate = inst.createRequestToken;
            inst.createRequestToken = makeNative(async function () {
                const token = await origCreate.apply(this, arguments);
                if (token) {
                    window.__CASTLE_TOKENS.push({
                        token: token,
                        timestamp: Date.now()
                    });
                    log('Castle V3 Token captured:', token);
                    window.dispatchEvent(new CustomEvent('castle_token_ready', { detail: { token } }));
                }
                return token;
            }, 'createRequestToken');
        }
    };

    let _castleHolder = window.castle;
    Object.defineProperty(window, 'castle', {
        get: () => _castleHolder,
        set: (val) => {
            _castleHolder = val;
            hookCastleInstance(val);
        },
        configurable: true
    });

    log('Castle V3 Stealth Injector (Userscript) đã nạp thành công.');

})();
