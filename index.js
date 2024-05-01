import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import elliptic from 'elliptic';
import { configuration } from './configuration.js';
import pg from 'pg';
const { Pool } = pg;

const ec = new elliptic.ec('secp256k1');
const pool = new Pool(configuration);
const app = express();

const storageUploads = multer.diskStorage({
    destination: 'uploads/',
    filename: function(req, file, cb) {
        const filename = Buffer.from(file.originalname, 'latin1').toString();
        cb(null, filename);
    }
});

const storageVerify = multer.diskStorage({
    destination: 'downloads/',
    filename: function(req, file, cb) {
        const filename = Buffer.from(file.originalname, 'latin1').toString();
        cb(null, filename);
    }
});

const upload = multer({ storage: storageUploads });
const verify = multer({ storage: storageVerify});

app.get('/', function(req, res){
    res.sendFile(process.cwd() + '/index.html');
});

app.post('/upload', upload.single('document'), async (req,res) => {

    const newDocument = saveDocument(req);
    const hash = await generateHash(newDocument.path);
    const keys = generateKeys();
    const statusOfSavingInDB = await saveInDB(keys.publicKey, hash);
    const signature = cipherHash(keys.privateKey, hash);
    const statusOfSaving = addSignature(signature, newDocument.path);

    res.download(newDocument.path);
})

app.post('/validate', verify.single('document'), async (req, res) => {

    const newDocument = saveDocument(req);
    findSignatureIndex(newDocument.path, async (err, signature) => {
        if (err) {
            return res.status(500).send('Ошибка при поиске подписи');
        }
        const hash = await generateHash(newDocument.path);
        const publicKey = await findInDB(hash);

        const key = ec.keyFromPublic(publicKey, 'hex');

        const isValid = key.verify(hash, signature);

        if (isValid)
        {
            res.send("Подпись верна");
        }
        else
        {
            res.send("Подпись неверна");
        }
    });
})

function findSignatureIndex(filePath, callback)
{
    fs.open(filePath, 'r+', (err, fd) => {
        
        const signatureInfo = findLastTab(fd);

        if (signatureInfo)
        {
            fs.ftruncate(fd, signatureInfo.position, (err) => {
                fs.close(fd, (err) => {
                    if (err) return callback(err);
                    return callback(null, signatureInfo.signature);
                })
            })
        }
        else
        {
            fs.close(fd, (err) => {
                if (err) return callback(err);
            })
        }
    })
}

function readFromLastTab(fd, lastTabPosition) {
    const bufferSize = 1024;
    const buffer = Buffer.alloc(bufferSize);
    let bytesRead;
    let offset = lastTabPosition + 1;

    const buffers = [];

    do {
        bytesRead = fs.readSync(fd, buffer, 0, bufferSize, offset);
        buffers.push(buffer.slice(0, bytesRead));
        offset += bytesRead;
    } while (bytesRead === bufferSize);

    const concatenatedBuffer = Buffer.concat(buffers);

    const str = concatenatedBuffer.toString();

    return str;
}

function findLastTab(fd)
{
    const bufferSize = 1024;
    const buffer = Buffer.alloc(bufferSize);
    let bytesRead;
    let lastTabPosition = -1;
    let offset = 0;

    do 
    {
        bytesRead = fs.readSync(fd, buffer, 0, bufferSize, offset);
        const newlineIndex = buffer.lastIndexOf('\n', bytesRead - 1);
        if (newlineIndex !== -1) {
            lastTabPosition = offset + newlineIndex;
        }
        offset += bytesRead;
    } 
    while (bytesRead === bufferSize);

    if (lastTabPosition !== -1) 
    {
        const str = readFromLastTab(fd, lastTabPosition);

        return {
            signature: str,
            position: lastTabPosition
        };
    } 
    else 
    {
        return null;
    }
}

async function findInDB(hash)
{
    const client = await pool.connect();
    const text = 'SELECT * FROM data WHERE hash = $1';
    const values = [hash];
    const info = await client.query(text, values);
    client.release();

    if (info != null)
    {
        if (info.rows != null)
        {
            return info.rows[0].public_key;
        }

        return null;
    }
    
    return null;
}

function addSignature(signature, filepath)
{
    const signatureWithEndlines = `\n${signature}`;
    fs.appendFileSync(filepath, signatureWithEndlines);
    return "Changed"
}

function cipherHash(privateKey, hash)
{
    const key = ec.keyFromPrivate(privateKey, 'hex');
    const signature = key.sign(hash);
    return signature.toDER('hex');
}

async function saveInDB(publicKey, hash)
{
    const client = await pool.connect();
    const text = 'INSERT INTO data(public_key, hash) VALUES($1, $2) RETURNING *';
    const values = [publicKey, hash];
    const info = await client.query(text, values);
    client.release();
    return info;
}

function generateKeys()
{
    const keys = ec.genKeyPair();

    return {
        privateKey: keys.getPrivate(),
        publicKey: keys.getPublic().encode('hex')
    }
}

function generateHash(filepath)
{
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const input = fs.createReadStream(filepath);

        input.on('error', reject);

        input.on('data', (chunk) => {
            hash.update(chunk);
        })

        input.on('end', () => {
            resolve(hash.digest('hex'));
        })
    })
}

function saveDocument(requestData)
{
    const uploadedDocument = requestData.file;
    console.log(requestData.file, requestData.body);
    return requestData.file;
}

app.listen(3000);