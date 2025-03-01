$(document).ready(function() {
    document.getElementById('uploadForm').addEventListener('submit', function(event) {
        event.preventDefault(); 
        const file = document.getElementById('fileInput').files[0];
        const key = document.getElementById('key').value;
        const algorithm = document.getElementById('algorithm').value;
        
        const formData = new FormData();
        formData.append('file', file);
        formData.append('key', key);
        formData.append('algorithm', algorithm)

        if (algorithm == 'DES' || algorithm == 'AES'){
            const mode = document.getElementById('mode').value;
            formData.append('mode', mode)
        }

        let action = '';
        if (event.submitter.id === 'Encrypt') {
            action = 'encrypt';
        } else if (event.submitter.id === 'Decrypt') {
            action = 'decrypt';
        }

        formData.append('action', action);

        $.ajax({
            url: '/upload-file', 
            method: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                if (response.success) {
                    alert(action === 'encrypt' ? 'File berhasil dienkripsi!' : 'File berhasil didekripsi!');

                    var fileName = response.filename;
                    document.getElementById('fileName').textContent = 'File: ' + fileName;

                    var downloadLink = document.getElementById('downloadLink');
                    downloadLink.href = 'static/uploads/' + fileName;

                    document.getElementById('fileDetails').style.display = 'block';
                    document.getElementById('hasil').style.display = 'none';
                } else {
                    alert(response.message);
                }
            },
            error: function() {
                alert('Terjadi kesalahan!');
            }
        });
    });

    document.getElementById('uploadTeks').addEventListener('submit', function(event) {
        event.preventDefault(); 
        const text1 = document.getElementById('text1').value;
        const key1 = document.getElementById('key1').value;
        const algorithm1 = document.getElementById('algorithm1').value;

        const formData = new FormData();
        formData.append('text1', text1);
        formData.append('key1', key1);
        formData.append('algorithm1', algorithm1)

        if (algorithm1 == 'DES' || algorithm1 == 'AES'){
            const mode1 = document.getElementById('mode1').value;
            formData.append('mode1', mode1)
        }

        let action = '';
        if (event.submitter.id === 'Encrypt1') {
            action = 'encrypt1';
        } else if (event.submitter.id === 'Decrypt1') {
            action = 'decrypt1';
        }

        formData.append('action', action);

        $.ajax({
            url: '/upload-text', 
            method: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                if (response.success) {
                    var resultteks = response.resultteks;
                    document.getElementById('teksHasil').textContent = resultteks
                    document.getElementById('fileDetails').style.display = 'none';
                    document.getElementById('hasil').style.display = 'block';
                } else {
                    alert(response.message);
                }
            },
            error: function() {
                alert('Terjadi kesalahan!');
            }
        });
    });

    document.getElementById("algorithm").addEventListener("change", function() {
        var algorithm = this.value;
        var kontainer = document.getElementById("kontainer");

        if (algorithm === "DES" || algorithm === "AES") {
            kontainer.style.display = "block";
        } else {
            kontainer.style.display = "none";
        }
    });

    document.getElementById("algorithm1").addEventListener("change", function() {
        var algorithm = this.value;
        var kontainer = document.getElementById("kontainer1");

        if (algorithm === "DES" || algorithm === "AES") {
            kontainer.style.display = "block";
        } else {
            kontainer.style.display = "none";
        }
    });

});
