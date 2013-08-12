#!/bin/bash

init()
{
  getPYRETICDIR
  PYRETICMNDIR="${PYRETICDIR}/mininet"
  PYRETICMN="${PYRETICMNDIR}/mn"
  EXTRATOPS="${PYRETICMNDIR}/extra-topos.py"  
  PYRETIC_PY="pyretic.py"
  PYRETICPY="${PYRETICDIR}/${PYRETIC_PY}"
  CONTROLLER="--controller remote"
  listeningPort="6633"
  
  if [ -f "${PYRETICPY}" -a "${PYRETICPY}" = "`which ${PYRETIC_PY}`" ] ; then
    PYRETICISHERE=1
  fi
}

getPYRETICDIR()
{
  HERE=${PWD}
  PYRETICDIR=`dirname $0`
  cd ${PYRETICDIR}
  PYRETICDIR=${PWD}
  cd ${HERE}
}

getMN()
{
  if [ -x "${PYRETICMN}" ] ; then
    MN="${PYRETICMN}"
  else
    MN="mn"
  fi
}

getCUSTOMTOPOS()
{
  CUSTOMTOPOS=""
  
  if [ -f "${EXTRATOPS}" ] ; then
    CUSTOMTOPOS="--custom ${EXTRATOPS}"
  fi
}

validateNB()
{
  echo "NB: The $* you enter is not validated, please ensure that it is valid!"
}

getLISTENINGPORT()
{
  validateNB "port"
  echo -e "Please enter listening port[${listeningPort}]: \c"
  read port

  if [ ! -z "${port}" ] ; then
    listeningPort="${port}"
  fi
  
  LISTENINGPORT="port=${listeningPort}"
}

getLISTENINGIP()
{
  if [ ! "${PYRETICISHERE}" = "1" ] ; then
    validateNB "IP"
    echo -e "Please enter IP address of listener: \c"
    read ip

    if [ ! -z "${ip}" ] ; then
      LISTENINGIP="ip=${ip}"
    fi
  fi
}

getCONTROLLER()
{
  getLISTENINGPORT
  getLISTENINGIP

  CONTROLLER="${CONTROLLER},${LISTENINGPORT}"
  
  if [ ! -z "${LISTENINGIP}" ] ; then
    CONTROLLER="${CONTROLLER},${LISTENINGIP}"
  fi
}

doIt()
{
  getCUSTOMTOPOS
  getCONTROLLER

  OPTIONS="--mac ${CUSTOMTOPOS} ${CONTROLLER}"
  getMN
  
  sudo ${MN} -c
  
  echo "sudo ${MN} ${OPTIONS} $@"
  sudo ${MN} ${OPTIONS} $@
}

init $*
doIt $*

