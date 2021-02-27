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
  document.querySelector('#loading').style["display"] = "inline";
  document.querySelector('#error').style["display"] = "none";

  const file = document.querySelector('#file').files[0];
  fetch('https://1nlsyfjbcb.execute-api.eu-south-1.amazonaws.com/default/pka2xml', {
    method: 'POST',
    body: JSON.stringify({
      file: await toBase64(file),
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

    document.querySelector('#encode').disabled = false;
    document.querySelector('#loading').style["display"] = "none";
    editor.setValue(str, -1);
  }).catch(err => {
    console.log(`err: ${err}`);
    document.querySelector('#error').style["display"] = "display";
    document.querySelector('#error').innerHTML = err;
  }).finally(() => {
    document.querySelector('#loading').style["display"] = "none";
  });
}

async function Retrofit() {
  document.querySelector('#loading').style["display"] = "inline";
  document.querySelector('#error').style["display"] = "none";

  const file = document.querySelector('#file').files[0];
  fetch('https://1nlsyfjbcb.execute-api.eu-south-1.amazonaws.com/default/pka2xml', {
    method: 'POST',
    body: JSON.stringify({
      file: await toBase64(file),
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
    document.querySelector('#error').style["display"] = "display";
    document.querySelector('#error').innerHTML = err;
  }).finally(() => {
    document.querySelector('#loading').style["display"] = "none";
  });
}

async function Encode() {
  const str = editor.getValue();

  if (str.length > 0 && editor.getSession().getAnnotations().some(x => x['type'] == 'error')) {
    return;
  }

  document.querySelector('#loading').style["display"] = "inline";
  document.querySelector('#error').style["display"] = "none";

  const compressed = pako.deflate(new TextEncoder().encode(str));
  const b = new Blob([compressed], { type: 'application/octet-stream' });

  fetch('https://1nlsyfjbcb.execute-api.eu-south-1.amazonaws.com/default/pka2xml', {
    method: 'POST',
    body: JSON.stringify({
      file: await toBase64(b),
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
    document.querySelector('#error').style["display"] = "display";
    document.querySelector('#error').innerHTML = err;
  }).finally(() => {
    document.querySelector('#loading').style["display"] = "none";
  });
}

async function Update() {
  const file = document.querySelector('#file').files[0];
  if (file.name.endsWith('.pka') || file.name.endsWith('.pkt')) {
    document.querySelector('#decode').disabled = false;
    document.querySelector('#retrofit').disabled = false;
    document.querySelector('#encode').disabled = true;
    editor.setValue("", -1);
  } else if (file.name.endsWith('.xml')) {
    document.querySelector('#decode').disabled = true;
    document.querySelector('#retrofit').disabled = true;
    document.querySelector('#encode').disabled = false;
    editor.setValue(await loadFile(file), -1);
  } else {
    document.querySelector('#decode').disabled = true;
    document.querySelector('#retrofit').disabled = true;
    document.querySelector('#encode').disabled = true;
    editor.setValue("", -1);
  }
}
