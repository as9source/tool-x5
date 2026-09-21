/*
 * PDFをメールなどで送る際に、パスワード付きZIPとして送信できるようにする共通部品。
 * ZIP暗号化には、Windowsの標準展開機能やMacの標準アーカイブユーティリティでも
 * パスワード解除できる「伝統的PKZIP暗号（ZipCrypto）」を実装している（追加ソフト不要）。
 * どのアプリからも <script src="pdf-zip-lock.js"></script> を読み込むだけで
 * window.PdfZipLock が使えるようになる。
 */
(function(global){
  'use strict';

  function isDesktopDevice(){
    var ua = navigator.userAgent;
    if (/Windows NT/i.test(ua)) return true;
    if (/Macintosh/i.test(ua) && !(navigator.maxTouchPoints > 1)) return true;
    return false;
  }

  // ───────── CRC32 ─────────
  var CRC_TABLE = (function(){
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crcStep(crc, byte){
    return (CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8)) >>> 0;
  }

  function crc32(bytes){
    var c = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) c = crcStep(c, bytes[i]);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  // ───────── 伝統的PKZIP暗号（ZipCrypto） ─────────
  function makeKeyState(password){
    var k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
    function update(byte){
      k0 = crcStep(k0, byte);
      k1 = (k1 + (k0 & 0xFF)) >>> 0;
      k1 = (Math.imul(k1, 134775813) + 1) >>> 0;
      k2 = crcStep(k2, (k1 >>> 24) & 0xFF);
    }
    var pwBytes = new TextEncoder().encode(password);
    for (var i = 0; i < pwBytes.length; i++) update(pwBytes[i]);
    return {
      update: update,
      keystreamByte: function(){
        var temp = (k2 & 0xFFFF) | 2;
        return ((temp * (temp ^ 1)) >>> 8) & 0xFF;
      }
    };
  }

  function encryptWithZipCrypto(bytes, password, crc){
    var keys = makeKeyState(password);
    var header = new Uint8Array(12);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(header);
    // 末尾2バイトはCRCの上位バイトにして、展開ソフトがパスワード正誤を判定できるようにする
    header[10] = (crc >>> 16) & 0xFF;
    header[11] = (crc >>> 24) & 0xFF;

    var out = new Uint8Array(12 + bytes.length);
    var i, p;
    for (i = 0; i < 12; i++) {
      p = header[i];
      out[i] = p ^ keys.keystreamByte();
      keys.update(p);
    }
    for (i = 0; i < bytes.length; i++) {
      p = bytes[i];
      out[12 + i] = p ^ keys.keystreamByte();
      keys.update(p);
    }
    return out;
  }

  // ───────── ZIPコンテナ（単一ファイル・無圧縮格納） ─────────
  function dosDateTime(date){
    var t = ((date.getSeconds() >> 1) | (date.getMinutes() << 5) | (date.getHours() << 11)) & 0xFFFF;
    var d = (date.getDate() | ((date.getMonth() + 1) << 5) | ((date.getFullYear() - 1980) << 9)) & 0xFFFF;
    return { time: t, date: d };
  }

  async function toBytes(data){
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
    throw new Error('unsupported data type');
  }

  async function buildPasswordZip(entryName, data, password){
    var bytes = await toBytes(data);
    var nameBytes = new TextEncoder().encode(entryName);
    var crc = crc32(bytes);
    var enc = encryptWithZipCrypto(bytes, password, crc);
    var dt = dosDateTime(new Date());
    var flag = 0x0801; // bit0=暗号化 / bit11=UTF-8ファイル名
    var method = 0;    // 格納（無圧縮）

    var localHeader = new Uint8Array(30 + nameBytes.length);
    var dv = new DataView(localHeader.buffer);
    dv.setUint32(0, 0x04034b50, true);
    dv.setUint16(4, 20, true);
    dv.setUint16(6, flag, true);
    dv.setUint16(8, method, true);
    dv.setUint16(10, dt.time, true);
    dv.setUint16(12, dt.date, true);
    dv.setUint32(14, crc, true);
    dv.setUint32(18, enc.length, true);
    dv.setUint32(22, bytes.length, true);
    dv.setUint16(26, nameBytes.length, true);
    dv.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);

    var centralHeader = new Uint8Array(46 + nameBytes.length);
    dv = new DataView(centralHeader.buffer);
    dv.setUint32(0, 0x02014b50, true);
    dv.setUint16(4, 20, true);
    dv.setUint16(6, 20, true);
    dv.setUint16(8, flag, true);
    dv.setUint16(10, method, true);
    dv.setUint16(12, dt.time, true);
    dv.setUint16(14, dt.date, true);
    dv.setUint32(16, crc, true);
    dv.setUint32(20, enc.length, true);
    dv.setUint32(24, bytes.length, true);
    dv.setUint16(28, nameBytes.length, true);
    dv.setUint16(30, 0, true);
    dv.setUint16(32, 0, true);
    dv.setUint16(34, 0, true);
    dv.setUint16(36, 0, true);
    dv.setUint32(38, 0, true);
    dv.setUint32(42, 0, true); // ローカルヘッダーのオフセット（先頭からなので0）
    centralHeader.set(nameBytes, 46);

    var cdOffset = localHeader.length + enc.length;
    var cdSize = centralHeader.length;

    var eocd = new Uint8Array(22);
    dv = new DataView(eocd.buffer);
    dv.setUint32(0, 0x06054b50, true);
    dv.setUint16(4, 0, true);
    dv.setUint16(6, 0, true);
    dv.setUint16(8, 1, true);
    dv.setUint16(10, 1, true);
    dv.setUint32(12, cdSize, true);
    dv.setUint32(16, cdOffset, true);
    dv.setUint16(20, 0, true);

    return new Blob([localHeader, enc, centralHeader, eocd], { type: 'application/zip' });
  }

  // ───────── わかりやすいパスワード生成 ─────────
  function generatePassword(len){
    len = len || 8;
    var chars = '23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz'; // 紛らわしい 0/O/1/I/l を除外
    var bytes = new Uint8Array(len);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(bytes);
    else for (var i = 0; i < len; i++) bytes[i] = Math.floor(Math.random() * 256);
    var out = '';
    for (var j = 0; j < len; j++) out += chars[bytes[j] % chars.length];
    return out;
  }

  // ───────── UI（モーダル） ─────────
  var stylesInjected = false;
  function injectStyles(){
    if (stylesInjected) return;
    stylesInjected = true;
    var style = document.createElement('style');
    style.textContent =
      '.pzl-overlay{position:fixed;inset:0;z-index:99999;background:rgba(20,20,25,.55);' +
      'display:flex;align-items:center;justify-content:center;padding:16px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}' +
      '.pzl-dialog{background:#fff;border-radius:14px;max-width:360px;width:100%;box-shadow:0 12px 40px rgba(0,0,0,.3);overflow:hidden}' +
      '.pzl-head{padding:16px 18px 12px;font-size:16px;font-weight:700;color:#1f2937;border-bottom:1px solid #eee}' +
      '.pzl-body{padding:16px 18px}' +
      '.pzl-desc{margin:0 0 14px;font-size:12.5px;line-height:1.6;color:#555}' +
      '.pzl-label{display:block;font-size:12px;font-weight:600;color:#666;margin-bottom:6px}' +
      '.pzl-pwrow{display:flex;gap:6px;align-items:center}' +
      '.pzl-input{flex:1;min-width:0;padding:10px 12px;font-size:16px;letter-spacing:.5px;font-family:"JetBrains Mono",Menlo,Consolas,monospace;border:1.5px solid #ddd;border-radius:8px;box-sizing:border-box}' +
      '.pzl-input:focus{outline:none;border-color:#4b7bec}' +
      '.pzl-iconbtn{flex-shrink:0;width:40px;height:40px;border:1.5px solid #ddd;background:#fafafa;border-radius:8px;font-size:16px;cursor:pointer}' +
      '.pzl-hint{margin:8px 0 0;font-size:11px;color:#999}' +
      '.pzl-actions{display:flex;gap:8px;padding:12px 18px 18px}' +
      '.pzl-btn{flex:1;padding:11px 10px;border-radius:8px;border:none;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}' +
      '.pzl-btn-cancel{background:#f0f0f0;color:#444}' +
      '.pzl-btn-confirm{background:#4b7bec;color:#fff}' +
      '.pzl-btn-confirm:disabled{opacity:.5;cursor:default}' +
      '.pzl-status{display:flex;flex-direction:column;align-items:center;gap:10px;padding:8px 0 4px;text-align:center}' +
      '.pzl-spinner{width:30px;height:30px;border:3px solid #e2e8f0;border-top-color:#4b7bec;border-radius:50%;animation:pzl-spin 0.8s linear infinite}' +
      '@keyframes pzl-spin{to{transform:rotate(360deg)}}' +
      '.pzl-statustext{font-size:13px;color:#444}' +
      '.pzl-result{font-size:13px;color:#1f7a3d;font-weight:600}' +
      '.pzl-errortext{font-size:13px;color:#c0392b}' +
      '.pzl-pwshow{margin-top:10px;padding:10px 12px;background:#f4f6ff;border:1px solid #dbe2ff;border-radius:8px}' +
      '.pzl-pwshow-label{font-size:11px;color:#666;margin-bottom:4px}' +
      '.pzl-pwshow-row{display:flex;align-items:center;gap:8px}' +
      '.pzl-pwshow-val{flex:1;font-family:"JetBrains Mono",Menlo,Consolas,monospace;font-size:16px;letter-spacing:1px;color:#1f2937;word-break:break-all}' +
      '.pzl-copybtn{flex-shrink:0;padding:6px 10px;font-size:12px;border-radius:6px;border:1px solid #ccd3f5;background:#fff;cursor:pointer}';
    document.head.appendChild(style);
  }

  function run(opts){
    opts = opts || {};
    var getPdf = opts.getPdf;
    var shareTitle = opts.shareTitle || 'PDF';

    return new Promise(function(resolve){
      injectStyles();

      var overlay = document.createElement('div');
      overlay.className = 'pzl-overlay';
      var dialog = document.createElement('div');
      dialog.className = 'pzl-dialog';
      overlay.appendChild(dialog);

      var head = document.createElement('div');
      head.className = 'pzl-head';
      head.textContent = '🔒 パスワード付きZIPで送信';
      dialog.appendChild(head);

      var body = document.createElement('div');
      body.className = 'pzl-body';
      dialog.appendChild(body);

      var actions = document.createElement('div');
      actions.className = 'pzl-actions';
      dialog.appendChild(actions);

      function close(){
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        document.removeEventListener('keydown', onKeydown);
        resolve();
      }
      function onKeydown(e){
        if (e.key === 'Escape') close();
      }
      document.addEventListener('keydown', onKeydown);
      overlay.addEventListener('click', function(e){
        if (e.target === overlay) close();
      });

      function copyToClipboard(text){
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).catch(function(){});
        }
      }

      function showPasswordState(){
        body.innerHTML = '';
        actions.innerHTML = '';

        var desc = document.createElement('p');
        desc.className = 'pzl-desc';
        desc.textContent = 'PDFをこのパスワードで保護したZIPに変換してから送信します。相手には、このパスワードを電話やSMSなど別の方法で伝えてください。';
        body.appendChild(desc);

        var label = document.createElement('label');
        label.className = 'pzl-label';
        label.textContent = 'パスワード';
        body.appendChild(label);

        var row = document.createElement('div');
        row.className = 'pzl-pwrow';
        var input = document.createElement('input');
        input.className = 'pzl-input';
        input.type = 'text';
        input.autocomplete = 'off';
        input.spellcheck = false;
        input.value = generatePassword();
        var regenBtn = document.createElement('button');
        regenBtn.type = 'button';
        regenBtn.className = 'pzl-iconbtn';
        regenBtn.title = '作り直す';
        regenBtn.textContent = '🔄';
        regenBtn.addEventListener('click', function(){ input.value = generatePassword(); input.focus(); });
        row.appendChild(input);
        row.appendChild(regenBtn);
        body.appendChild(row);

        var hint = document.createElement('p');
        hint.className = 'pzl-hint';
        hint.textContent = 'そのまま送っても、書き換えても構いません。';
        body.appendChild(hint);

        var cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'pzl-btn pzl-btn-cancel';
        cancelBtn.textContent = 'キャンセル';
        cancelBtn.addEventListener('click', close);

        var confirmBtn = document.createElement('button');
        confirmBtn.type = 'button';
        confirmBtn.className = 'pzl-btn pzl-btn-confirm';
        confirmBtn.textContent = 'ZIPを作成して送信';
        confirmBtn.addEventListener('click', function(){
          var pw = input.value;
          if (!pw) { input.focus(); return; }
          startBuild(pw);
        });

        actions.appendChild(cancelBtn);
        actions.appendChild(confirmBtn);
        input.focus();
        input.select();
      }

      function showWorkingState(message){
        body.innerHTML = '';
        actions.innerHTML = '';
        var wrap = document.createElement('div');
        wrap.className = 'pzl-status';
        var spinner = document.createElement('div');
        spinner.className = 'pzl-spinner';
        var text = document.createElement('div');
        text.className = 'pzl-statustext';
        text.textContent = message;
        wrap.appendChild(spinner);
        wrap.appendChild(text);
        body.appendChild(wrap);
      }

      function showDoneState(password, resultMessage){
        body.innerHTML = '';
        actions.innerHTML = '';
        var wrap = document.createElement('div');
        wrap.className = 'pzl-status';
        var result = document.createElement('div');
        result.className = 'pzl-result';
        result.textContent = resultMessage;
        wrap.appendChild(result);

        var pwBox = document.createElement('div');
        pwBox.className = 'pzl-pwshow';
        var pwLabel = document.createElement('div');
        pwLabel.className = 'pzl-pwshow-label';
        pwLabel.textContent = 'ZIPのパスワード（相手に別途お伝えください）';
        var pwRow = document.createElement('div');
        pwRow.className = 'pzl-pwshow-row';
        var pwVal = document.createElement('div');
        pwVal.className = 'pzl-pwshow-val';
        pwVal.textContent = password;
        var copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'pzl-copybtn';
        copyBtn.textContent = 'コピー';
        copyBtn.addEventListener('click', function(){
          copyToClipboard(password);
          copyBtn.textContent = 'コピー済み';
          setTimeout(function(){ copyBtn.textContent = 'コピー'; }, 1500);
        });
        pwRow.appendChild(pwVal);
        pwRow.appendChild(copyBtn);
        pwBox.appendChild(pwLabel);
        pwBox.appendChild(pwRow);
        wrap.appendChild(pwBox);
        body.appendChild(wrap);

        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'pzl-btn pzl-btn-confirm';
        closeBtn.style.flex = '1 1 100%';
        closeBtn.textContent = '閉じる';
        closeBtn.addEventListener('click', close);
        actions.appendChild(closeBtn);
      }

      function showErrorState(message){
        body.innerHTML = '';
        actions.innerHTML = '';
        var wrap = document.createElement('div');
        wrap.className = 'pzl-status';
        var text = document.createElement('div');
        text.className = 'pzl-errortext';
        text.textContent = message;
        wrap.appendChild(text);
        body.appendChild(wrap);

        var backBtn = document.createElement('button');
        backBtn.type = 'button';
        backBtn.className = 'pzl-btn pzl-btn-cancel';
        backBtn.textContent = '閉じる';
        backBtn.addEventListener('click', close);
        actions.appendChild(backBtn);
      }

      async function startBuild(password){
        showWorkingState('PDFを生成しています…');
        var built;
        try {
          built = await getPdf();
        } catch (e) {
          console.error(e);
          showErrorState('PDFの生成に失敗しました。');
          return;
        }
        if (!built || !built.file) {
          // getPdf側で既に案内済み（未入力など）と判断し、静かに閉じる
          close();
          return;
        }

        showWorkingState('パスワード付きZIPを作成しています…');
        var zipBlob;
        try {
          zipBlob = await buildPasswordZip(built.name, built.file, password);
        } catch (e) {
          console.error(e);
          showErrorState('ZIPの作成に失敗しました。');
          return;
        }

        var zipName = (built.name || 'file.pdf').replace(/\.pdf$/i, '') + '.zip';
        var zipFile = new File([zipBlob], zipName, { type: 'application/zip' });

        var canShareFile = !isDesktopDevice() && typeof navigator.share === 'function' &&
          (typeof navigator.canShare !== 'function' || navigator.canShare({ files: [zipFile] }));

        if (canShareFile) {
          showWorkingState('送信先を選んでください…');
          try {
            await navigator.share({ files: [zipFile], title: shareTitle, text: zipName });
            showDoneState(password, '✅ 送信しました');
          } catch (e) {
            if (e && e.name === 'AbortError') { close(); return; }
            console.error(e);
            showErrorState('送信に失敗しました。');
          }
        } else {
          try {
            var url = URL.createObjectURL(zipFile);
            var a = document.createElement('a');
            a.href = url; a.download = zipName; a.click();
            setTimeout(function(){ URL.revokeObjectURL(url); }, 5000);
            showDoneState(password, '💾 ZIPをダウンロードしました。メールに添付して送信してください。');
          } catch (e) {
            console.error(e);
            showErrorState('ダウンロードに失敗しました。');
          }
        }
      }

      document.body.appendChild(overlay);
      showPasswordState();
    });
  }

  global.PdfZipLock = {
    buildPasswordZip: buildPasswordZip,
    generatePassword: generatePassword,
    run: run
  };
})(window);
