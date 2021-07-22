const router = require("express").Router()

const bcryptjs = require("bcryptjs")

const mongoose = require("mongoose")

const User = require('./../models/User.model')

const { isLoggedIn, isLoggedOut } = require('./../middleware/routh-guard')





// GET - Display the signup for
router.get("/signup", isLoggedOut, (req, res) => {
    res.render("auth/signup")
})
// POST - Process form data
router.post("/signup", (req, res) => {
    // EXTRACCIÓN DE VALORES A UNA VARIABLE
    const { username, email, password } = req.body
    // VALIDAR QUE NO LLEGUEN DATOS VACÍOS
    if (!username || !email || !password) {
        return res.render('auth/signup', {
            msg: "Todos los campos son obligatorios"
        })
    }
    // VERIFICAR QUE EL PASSWORD ES FUERTE (TIENE UNA COMBINACIÓN DÍFICIL DE LEER)
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    // Si el password no cumple con las expectativas del regex
    if (!regex.test(password)) {
        return res.status(500).render("auth/signup", {
            msg: "El password debe tener 6 caracteres mínimo y debe contener al menos un número, una minúscula y una mayúscula."
        })
    }
    // ENCRIPTACIÓN
    bcryptjs
        .genSalt(10)
        .then(salt => bcryptjs.hash(password, salt))
        .then(hashedPassword => {
            return User.create({
                username,
                email,
                passwordHash: hashedPassword
            })
        })
        .then(usuarioCreado => {
            console.log("El usuario que creamos fue:", usuarioCreado)
            res.redirect('/userprofile')
        })
        .catch(e => {
            if (e instanceof mongoose.Error.ValidationError) {
                res.status(500).render("auth/signup", {
                    msg: "Usa un email válido"
                })
            } else if (e.code === 11000) {
                res.status(500).render("auth/signup", {
                    msg: "El usuario y el correo ya existen. Intenta uno nuevo."
                })
            }
        })
})


//GET Profile Page for current user

//SI ESTOY LOGGEADO, PUEDO ENTRAR  A USERPROFILE
//SI NO ESTOY LOGGEADO, ENVÍAME A LA PÁGINA LOGIN

router.get('/userprofile', isLoggedIn, (req, res) => {
    res.render("user/user-profile", { usuarioActual: req.session.usuarioActual })
})

//GET - Mostrar el formulario login

router.get("/login", (req, res) => {
    res.render("auth/login")
})

// POST - PROCESO DE AUTENTICACIÓN
// VERIFICAR QUE EL USUARIO QUE ESTÁ PASANDO SU EMAIL Y CONTRASEÑA ES REALMENTE EL MISMO QUE SE REGISTRÓ
router.post("/login", (req, res) => {

    console.log(req.session)

    const { email, password } = req.body


    // VALIDAR EMAIL Y PASSWORD
    if (!email || !password) {
        return res.render("auth/login", {
            msg: "Por favor ingresa email y password."
        })
    }
    User.findOne({ email })
        .then((usuarioEncontrado) => {

            

        // 1. EL USUARIO NO EXISTE EN BASE DE DATOS
        if (!usuarioEncontrado) {
        return res.render("auth/login", {
            msg: "El email no fue encontrado"
        })
    }
    const autenticacionVerificada = bcryptjs.compareSync(password, usuarioEncontrado.passwordHash)
    //2. SI EL USUARIO SE EQUIVOCÓ EN LA CONTRASEÑA
    if (!autenticacionVerificada) {
        return res.render("auth/login", {
            msg: "La contraseña es incorrecta"
        })
    }

    // 3. SI EL USUARIO COINCIDE LA CONTRASEÑA CON LA BASE DE DATOS

        //vamos a crear en nuestro objeto SESSION una propiedad nueva que se llame usuarioActual
        
        req.session.usuarioActual = usuarioEncontrado

        console.log("sesión actualidad", req.session)
        return res.redirect("/userprofile")

    
       
      })
    .catch((e) => console.log(e))
  })


  //POST - CERRAR SESIÓN

  router.post('/logout', (req, res) => {
    req.session.destroy(e => {
      if(e){
        console.log(e)
      }
      res.redirect("/")
    })
  
  })
module.exports = router