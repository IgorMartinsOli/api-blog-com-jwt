const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const Usuario = require('./usuarios-modelo');
const {InvalidArgumentError} = require('../erros');
const bcrypt = require('bcrypt');
const BearerStrategy = require('passport-http-bearer').Strategy;
const jwt = require('jsonwebtoken');

function verificaUsuario(usuario) {
    if(!usuario){
        throw new InvalidArgumentError('Não existe usuario com esse e-mail');
    }
}

async function verificaSenha(senha, senhaHash) {
    const senhaValida = await bcrypt.compare(senha, senhaHash);
    if (!senhaValida) {
        throw new InvalidArgumentError('E-mail ou senha inválidos!');
    }
}

passport.use(
    new LocalStrategy({
        usernameField: 'email',
        passwordField: 'senha',
        session: false
    },
    async (email, senha, done) => {
        try {
            const usuario = await Usuario.buscaPorEmail(email);
            console.log(usuario)
            verificaUsuario(usuario);
            await verificaSenha(senha, usuario.senhaHash);
            done(null, usuario);
        } catch (erro) {
            done(erro);
        }
    }
    )
);

passport.use(
    new BearerStrategy(
        async (token, done) => {
            try {
            const payload = jwt.verify(token, process.env.CHAVEJWT);
            const user = await Usuario.buscaPorId(payload.id);
            done(null, user, {token: token});
            }catch (err) {
                done(err);
            }
        }
    )
)