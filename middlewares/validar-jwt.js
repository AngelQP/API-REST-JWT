const jwt = require('jsonwebtoken');

const Usuario = require('../models/usuario');

const validarJWT = async (req, res, next) => {

  const token = req.header('x-token'); // Asi se especifica en el POSTMAN

  if( !token ) {
    return res.status(401).json({
      msg: 'No hay token en la peticion'
    })
  } 

  try {

    const {uid} = jwt.verify( token, process.env.SECRETORPRIVATEKEY);

    // leer el usuario que corresponde al uid 
    const usuario = await Usuario.findById(uid);

    // Verificar si existe un usuario con el uid
    if(!usuario) {
      return res.status(401).json({
        msg: 'Token no válido - usuario no existe en DB'
      })
    }

    // Verificar si el uid tiene estado en true
    if(!usuario.estado) {
      return res.status(401).json({
        msg: 'Token no válido - usuario con estado false'
      })
    }

    req.usuario = usuario;

    next();

  } catch (error) {

    console.log(error);
    res.status(401).json({
      msg: 'Token no válido'
    })
  }

}

module.exports = {
  validarJWT
}