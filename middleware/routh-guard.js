/*
*  /signup - GET - isLoggedOut
* /signup -POST -isloggeOut
*  /login - GET - isLoggedOut
* /login -POST -isloggeOut
* /logout -POST -isloggeIn
* /userprofile -GET - isloggedIn
*/  


const isLoggedIn = (req, res, next) => {
    if(!req.session.usuarioActual) {
        return res.redirect("/login")
    }

    next()
}

const isLoggedOut = (req, res, next) => {
    if(req.session.usuarioActual){   //si ya está loggeado que no entre a signup
        return res.redirect("/")
    }

    next()
}

module.exports = {
    isLoggedIn,
    isLoggedOut
}