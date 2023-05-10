const Role = require('../models/role');
const Usuario = require('../models/usuario');

const esRoleValido = async (rol = '') => {
  const existeRol = await Role.findOne({rol});
  if( !existeRol ){
    throw new Error(`El rol ${rol} no esta registrado en la base de datos`)    
  }
};

// TODO Verificar si el correo existe

const emailExiste = async (correo = '') => {

  const correoExiste = await Usuario.findOne({correo});
    if ( correoExiste ){
      throw new Error(`El correo ${correo} ya esta registrado en la base de datos`)  
    }
} 

// TODO Verificar si el id existe para el usuario

const existeUsuarioPorId = async (id) => {

  // Verificar si el usuario existe
  const existeUsuario = await Usuario.findById(id);
    if ( !existeUsuario ){
      throw new Error(`El id ${id} no existe para un usuario`)  
    }
} 


module.exports = {
  esRoleValido,
  emailExiste,
  existeUsuarioPorId
};