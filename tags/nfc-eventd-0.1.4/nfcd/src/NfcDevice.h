#ifndef NFCDEVICE_H
#define NFCDEVICE_H

#include <QObject>
#include <QStringList>
#include <QUuid>
#include <QMutex>
#include <unistd.h>

#include <nfc/nfc.h>
#include <freefare.h>
#include "iso14443b.h"


class NfcTarget;

/// NfcDevice
/**
  * This class handle a NFC Device
  */

class NfcDevice : public QObject
{
    Q_OBJECT

public:

  NfcDevice(const uchar, const nfc_device_desc_t, QMutex*);


  const QString getName();

  const QUuid getUuid();

  const QString getPath();

  void setPath(QString);

public Q_SLOTS:

  const uchar getId();

  void checkAvailableTargets();

  QStringList getTargetList();

  QString getTargetPathByUid(QString);

Q_SIGNALS:

  /// signal emitted when a target enter the field
  void targetAdded(QString uid, QString name);

  /// signal emitted when a target leave the field
  void targetRemoved(QString uid, QString name);

protected:

  /// id of the device
  uchar _id;

  /// descriptor of the device
  nfc_device_desc_t _device;

  /// pointer to the device
  nfc_device_t* _device_connect;

  /// uuid of the device
  QUuid _uuid;

  /// DBUS path of this object
  QString _dbusPath;

  /// mutex protecting the access of the device
  QMutex* _accessLock;

  void timerEvent(QTimerEvent *event);

  /// register a new target
  void registerTarget(NfcTarget* target);

  /// unregister a target
  void unregisterTarget(NfcTarget* target);

private:

  /// contain the targets of this device
  QList<NfcTarget*> targets;
};

#endif // NFCDEVICE_H
