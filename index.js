import express from 'express'; // бекенд
import multer from 'multer'; // загрузка и выгрузка документов
import crypto from 'crypto'; // хеширование (SHA-256)
import fs from 'fs'; // работа с содержимым документов
import elliptic from 'elliptic'; // библиотека, реализующая ECDSA (Elliptic Curve Digital Signature Algorithm)
import { configuration } from './configuration.js';
import pg from 'pg'; // библиотека для подключения к БД
const { Pool } = pg;

/*

Описание ECDSA

1) Генерация параметров для эллиптической кривой (в elliptic используются заранее заготовленные параметры):

Выбирается q (огромное простое число), L ((160 <= L <= [log2(q)]) && (2^L >= 4*sqrt(q)))
1.1) Абсолютно случайно выбираются натуральные a и b не превышающие q, которые удовлетворяют условию: 4a^3 + 27b^2 не эквивалентна 0 по модулю q
1.2) Вычисляется порядок кривой (принимается за N) y^2 = x^3 + ax + b (количество целых точек, которые также меньше q)
1.3) Проверка того, что N mod n = 0, при большом простом n >= 2^L. Если N не делится нацело на n, то возвращаются к (1.1)
1.4) Проверка, что q^k - 1 mod n = 0 для любого натурального k принадлежащего [1,20]. Иначе - возврат к (1.1)
1.5) Проверка, что n != q. Иначе - опять к (1.1)
1.6) h = N/n
1.7) Выбирается произвольная точка G, которая принадлежит кривой и координаты которой не превышают q. Раз за разом, точку умножают на h, пока она не станет бесконечно удалённой точкой (координаты станут больше q (берётся значение до этого шага))

Получили - q, a, b, G(x,y), n

2) Генерация открытого и закрытого ключа
2.1) Выбирается случайное целое число d принадлежащее [1, n-1]
2.2) Вычисляются координаты Q = dG

Q(x,y) - открытый ключ, а d - закрытый

3) Генерация цифровой подписи (нужен закрытый ключ)
3.1) Выбирается случайное целое число k принадлежащее [1, n-1]
3.2) Вычисляются координаты kG = (x1,y1)
3.3) Вычисляется r = x1 mod n, если r = 0, то повторяется (3.1)
3.4) Вычисляется хеш для сообщения (Обозначим хеш - e) (файла, документа и т.д). Вычислением хеша ECDSA не занимается - используется сторонний алгоритм, например SHA-256
3.5) Вычисляется s = k^(-1)(e + dr) mod n. Если s = 0 - возврат к (3.1)

(r,s) - подпись

4) Проверка достоверности подписи (нужен открытый ключ) (r,s)
4.1) Проверяется, что r и s - целые, входящие в диапазон [1,n-1]. Если нет - недействительна
4.2) Вычисляется хеш сообщения (документа, файла и т.д.)
4.3) w = s^(-1) mod n
4.4) u1 = ew mod n, u2 = rw mod n
4.5) Вычисляется X = (x2, y2) = u1*G + u2*Q
4.6) Если X получился бесконечно удалённой точкой (вышел из диапазона), то подпись не действительна
4.7) v = x2 mod n. Если v = r, то подпись действительна, иначе - нет

*/

const ec = new elliptic.ec('secp256k1'); // эллиптическая кривая, с параметрами a = 0, b = 7 (используется в Ethereum и Bitcoin). Другие параметры (G, n, q) не приведены, так как велики
const pool = new Pool(configuration);
const app = express();

// Для того, чтобы определить директорию сохранения файлов
const storageUploads = multer.diskStorage({
    destination: 'uploads/',
    filename: function(req, file, cb) {
        const filename = Buffer.from(file.originalname, 'latin1').toString(); // Для корректного сохранения имени файла, состоящего не из ASCII
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
    res.sendFile(process.cwd() + '/index.html'); //Основная страница приложения
});

app.post('/upload', upload.single('document'), async (req,res) => {

    const newDocument = saveDocument(req);
    const hash = await generateHash(newDocument.path);
    const keys = generateKeys();
    const statusOfSavingInDB = await saveInDB(keys.publicKey, hash);
    const signature = cipherHash(keys.privateKey, hash);
    const statusOfSaving = addSignature(signature, newDocument.path);

    /*
    1. Сохранение документа
    2. Генерация хеша
    3. Генерация ключей
    4. Сохранение хеша и открытого ключа в БД
    5. Шифрование хеша с помощью закрытого ключа
    6. Добавление подписи в конец документа
    */

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

    /*
    1. Сохранение документа
    2. Получение подписи и стирание подписи из полученного документа (для корректного вычисление хеша)
    3. Генерация хеша
    4. Получение по хешу из БД публичного ключа
    5. Сравнение хеша и подписи, расшифрованной публичным ключом
    */
})

function findSignatureIndex(filePath, callback)
{
    fs.open(filePath, 'r+', (err, fd) => {
        
        const signatureInfo = findLastTab(fd);

        if (signatureInfo)
        {
            fs.ftruncate(fd, signatureInfo.position, (err) => { // удаление содержимого, начиная с найденного индекса и до конца (иначе хеш будет неправильным (в оригинальном файле не было подписи))
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
        bytesRead = fs.readSync(fd, buffer, 0, bufferSize, offset); // соединяем буферы - по 1024 байта в одну строку, начиная с найденного индекса (последний перенос строки) до конца файла
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
        bytesRead = fs.readSync(fd, buffer, 0, bufferSize, offset); // проходимся по 1024 байта и ищем последний перенос строки
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
    const client = await pool.connect(); // тут всё очевидно
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
    fs.appendFileSync(filepath, signatureWithEndlines); // добавление в конец файла подписи с переносом строки перед ним, чтобы затем его можно было бы найти
    return "Changed"
}

function cipherHash(privateKey, hash)
{
    const key = ec.keyFromPrivate(privateKey, 'hex'); // по значению приватного ключа - строки, создаёт объект - ключ с методами из библиотеки elliptic
    const signature = key.sign(hash); // шифрование хеша с использованием закрытого ключа
    return signature.toDER('hex'); // представление подписи в виде одной строки (по умолчанию - подпись состоит из r и s)
}

async function saveInDB(publicKey, hash)
{
    const client = await pool.connect(); // тут всё очевидно
    const text = 'INSERT INTO data(public_key, hash) VALUES($1, $2) RETURNING *';
    const values = [publicKey, hash];
    const info = await client.query(text, values);
    client.release();
    return info;
}

function generateKeys()
{
    const keys = ec.genKeyPair(); // Генерирует открытый и закрытый ключ, причём keys.getPublic() - возвращает координаты x, y точки G - точка принадлежащая эллиптической кривой y^2 = x^3 + ax + b, encode представляет его в виде одного 16-ричного числа

    return {
        privateKey: keys.getPrivate(),
        publicKey: keys.getPublic().encode('hex')
    }
}

function generateHash(filepath)
{
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256'); // sha256 - один из криптостойких алгоритмов хеширования
        const input = fs.createReadStream(filepath); // Для работы с документом, расположенным по указанному пути

        input.on('error', reject);

        input.on('data', (chunk) => {
            hash.update(chunk); // хеш вычисляется постепенно, при работе с содержимым документа, как с потоком (у метода есть описание из самой библиотеки)
        })

        input.on('end', () => {
            resolve(hash.digest('hex')); // Финальное значение хеша на основе данных, переданных кусками (у метода есть описание из самой библиотеки)
        })
    })
}

function saveDocument(requestData)
{
    const uploadedDocument = requestData.file;
    return requestData.file;
}

app.listen(3000);