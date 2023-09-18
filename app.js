require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express()
app.use(express.json())
const PORT = 3000

//Models
const User = require('./models/User')

//ROTA PUBLICA
app.get('/', (req, res) => {
    res.status(200).json({ message: 'funcionou' })
})

//PRIVATE ROUTE
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id

    //checar existencia user
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ message: 'usuario nao encontrado' })
    }

    return res.status(200).json({ user })
})

//MIDDLEWARE
function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ message: 'acesso negado' })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({message: 'token invalido'})
    }
}

//REGISTRO USUARIO
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body

    //validacoes
    if (!name) {
        return res.status(422).json({ message: 'nome obrigatorio' })
    }
    if (!email) {
        return res.status(422).json({ message: 'email obrigatorio' })
    }
    if (!password) {
        return res.status(422).json({ message: 'senha obrigatorio' })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ message: 'senhas nao sao iguais' })
    }

    //checar se usuario ja existe
    const userExist = await User.findOne({ email: email })

    if (userExist) {
        return res.status(422).json({ message: 'este email ja esta sendo usado' })
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save()

        res.status(200).json({ message: 'usuario cadrastado' })
    } catch (error) {
        res.status(500).json({ message: error })
    }
})

//LOGIN USUARIO
app.post('/auth/login', async (req, res) => {

    const { email, password } = req.body

    //validacoes
    if (!email) {
        return res.status(422).json({ message: 'email obrigatorio' })
    }
    if (!password) {
        return res.status(422).json({ message: 'senha obrigatorio' })
    }

    //checar existencia
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ message: 'usuario nao cadastradoo' })
    }

    //checar senha
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ message: 'senha invalida' })
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,
        },
            secret,
        )

        res.status(200).json({ message: 'atuenticacao realizada com sucesso', token })

    } catch (error) {
        res.status(500).json({ message: error })
    }
})

//NAO DAR COMIT COM USUARIO E SENHA, USAR PORRA .ENV QUE NAO FUNCIONA
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const uri = (`mongodb+srv://${DB_USER}:${DB_PASSWORD}@cluster0.lj0odv1.mongodb.net/?retryWrites=true&w=majority`)
mongoose.connect(uri)
    .then(app.listen(PORT, () => {
        console.log("conectamos ao mongoDB")
        console.log("rodando na porta 3000....")
    }))
    .catch((err) => console.log(err))

