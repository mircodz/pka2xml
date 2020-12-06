const toBase64 = file => new Promise((resolve, reject) => {
  const reader = new FileReader();
  reader.readAsDataURL(file);
  reader.onload = () => resolve(reader.result);
  reader.onerror = error => reject(error);
});

const b64toBlob = (base64, type = 'application/octet-stream') =>
  fetch(`data:${type};base64,${base64}`).then(res => res.blob());

async function loadFile(file) {
  return await file.text();
}

async function Decode() {
  const file = document.querySelector('#file').files[0];
  fetch('https://1nlsyfjbcb.execute-api.eu-south-1.amazonaws.com/default/pka2xml', {
    method: 'POST',
    body: JSON.stringify({
      // encode to base64 and discard url path
      file: (await toBase64(file)).substring(30),
      action: 'decode',
    })
  }).then(response => response.text())
  .then(b64toBlob)
  .then(blob => blob.arrayBuffer())
  .then(result => {
    const data = pako.inflate(new Uint8Array(result));
    const str = new TextDecoder("utf-8").decode(data);

    const b = new Blob([str], { type: 'application/octet-stream' });
    const a = document.createElement('a');
    a.download = document.querySelector('#file').files[0].name.replace('.pka', '.xml');
    a.href = window.URL.createObjectURL(b);
    a.click();

    editor.setValue(str, -1);
  }).catch(err => {
      console.log(`err: ${err}`);
  });
}

async function Retrofit() {
  const file = document.querySelector('#file').files[0];
  fetch('https://1nlsyfjbcb.execute-api.eu-south-1.amazonaws.com/default/pka2xml', {
    method: 'POST',
    body: JSON.stringify({
      // encode to base64 and discard url path
      file: (await toBase64(file)).substring(30),
      action: 'retrofit',
    })
  }).then(response => response.text())
  .then(b64toBlob)
  .then(result => {
    const a = document.createElement('a');
    a.download = document.querySelector('#file').files[0].name;
    a.href = window.URL.createObjectURL(result);
    a.click();
  }).catch(err => {
    console.log(`err: ${err}`);
  });
}

async function Encode() {
  const str = editor.getValue();

  if (str.length > 0 && editor.getSession().getAnnotations().some(x => x['type'] == 'error')) {
    return;
  }

  const compressed = pako.deflate(new TextEncoder().encode(str));
  const b = new Blob([compressed], { type: 'application/octet-stream' });

  fetch('https://1nlsyfjbcb.execute-api.eu-south-1.amazonaws.com/default/pka2xml', {
    method: 'POST',
    body: JSON.stringify({
      // encode to base64 and discard url path
      file: (await toBase64(b)).substring(30),
      action: 'encode',
      length: str.length,
    })
  }).then(response => response.text())
  .then(b64toBlob)
  .then(result => {
    const a = document.createElement('a');
    a.download = document.querySelector('#file').files[0].name.replace('.xml', '.pka');
    a.href = window.URL.createObjectURL(result);
    a.click();
  }).catch(err => {
    console.log(`err: ${err}`);
  });
}

async function Open() {
  const file = document.querySelector('#file').files[0];
  editor.setValue(await loadFile(file), -1);
}
