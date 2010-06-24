#include "NfcDevice.h"

#include "NfcTarget.h"
#include "nfctargetadaptor.h"

#include <QDebug>
#include <QtDBus>
#include <QtDBus/QDBusConnection>

#include <stdlib.h>

/**
 * @brief construct a device with the given id, descriptor and mutex
 * @param devicId id of the device
 * @param device the descriptor of the device
 * @param accessLock mutex locking this device's access
 */
NfcDevice::NfcDevice(const uchar deviceId, const nfc_device_desc_t device,
  QMutex* accessLock) : _id (deviceId)
{
  _device = device;
  _device_connect = nfc_connect(&_device);
  _uuid = QUuid::createUuid();
  _dbusPath = "";
  _accessLock = accessLock;	
}

/// get device name
const QString NfcDevice::getName()
{
  return QString(_device.acDevice);
}

/// getter for _uuid
const QUuid NfcDevice::getUuid() {
  return _uuid;
}

/// getter for _dbusPath
const QString NfcDevice::getPath() {
	return _dbusPath;
}

/// getter for _id
const uchar NfcDevice::getId()
{
  return _id;
}

/// get the DBUS path of the target with the given uid
QString NfcDevice::getTargetPathByUid(QString tgUid)
{
  QString path = "";
  for(int i=0; i<targets.size(); i++) {
    if(tgUid == targets.at(i)->getUid()) 
		path = targets.at(i)->getPath();
  }
  return path;
}

/** 
 * @brief setter for _dbusPath
 * @param s new D-Bus path
 */
void NfcDevice::setPath(QString s) {
	_dbusPath = s;
} 

/// get the target list for this device
QStringList NfcDevice::getTargetList()
{
  QStringList targetUids;
  for(int i=0; i<targets.size(); i++) {
    targetUids << targets.at(i)->getUid();
  }
  return targetUids;
}


void NfcDevice::timerEvent(QTimerEvent *event)
{
  Q_UNUSED(event);

  qDebug ("NfcDevice::timerEvent");
}

/// checking for new targets or missing targets
void NfcDevice::checkAvailableTargets()
{
  _accessLock->lock();
  if(_device_connect) {
    /* We are connected to NFC device */
    MifareTag *tags = NULL;
    tags = freefare_get_tags (_device_connect);
    if (tags != NULL) {
      int i = 0;
      MifareTag tag;

      /* Look for disapeared devices */
      for(i = 0; i < targets.size(); i++) {
        bool still_here = false;
        int j = 0;
        while(tag = tags[j]) {
          char* u = freefare_get_tag_uid(tag);
          QString uid(u);
          free(u);

          if(targets.at(i)->getUid() == uid) {
            still_here = true;
            break;
          }
          j++;
        }
        if(!still_here) {
          unregisterTarget(targets.at(i));
        }
      }

      /* Look for new devices */
      i = 0;
      while((tag = tags[i])) {
        char* u = freefare_get_tag_uid(tag);
        QString uid(u);
        free(u);

        bool already_known = false;
        for(int j=0; j < targets.size(); j++) {
          if(targets.at(j)->getUid() == uid) {
            already_known = true;
            break;
          }
        }
        if(!already_known) {
          registerTarget(tag);
        }
        i++;
      }
    }
  }
  _accessLock->unlock();
}

void
NfcDevice::registerTarget(MifareTag tag)
{
  NfcTarget* nfcTarget = new NfcTarget(tag, _accessLock);
  targets << nfcTarget;
  new NfcTargetAdaptor(nfcTarget);

  QDBusConnection connection = QDBusConnection::systemBus();
  QString path = QString("/nfcd") + QString("/target_") 
		+ nfcTarget->getUuid().toString().remove(QRegExp("[{}-]"));
  if( connection.registerObject(path, nfcTarget) ) {
    qDebug() << "Device \"" << nfcTarget->getName() << "\" is D-Bus registred (" << path << ").";
	 nfcTarget->setPath(path);
    emit targetFieldEntered(nfcTarget->getUid(), nfcTarget->getName());
  } else {
	 qDebug() << connection.lastError().message();
    qFatal("Unable to register a new device on D-Bus.");
  }

}

void NfcDevice::unregisterTarget(NfcTarget* target)
{
  QString uid = target->getUid();
  QString name = target->getName();

  for(int i=0; i<targets.size(); i++) {
    if(targets.at(i) == target) {
      NfcTarget* nfcTarget = targets.takeAt(i);
      QDBusConnection connection = QDBusConnection::systemBus();
      QString path = QString("/nfcd") + QString("/target_") 
        + nfcTarget->getUuid().toString().remove(QRegExp("[{}-]"));
      connection.unregisterObject(path);

      qDebug() << "Device \"" << name << "\" is D-Bus unregistred (" << path << ").";
      delete(nfcTarget);
      break;
    }
  }
  emit targetFieldLeft (uid, name);
}

