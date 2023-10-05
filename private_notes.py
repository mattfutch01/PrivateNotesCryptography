import pickle
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class PrivNotes:
  MAX_NOTE_LEN = 2048

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    self.nonce = 1
    self.kvs = {}
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = os.urandom(16), iterations = 2000000, backend = default_backend())    
    self.sourceKey = kdf.derive(bytes(password, 'ascii'))
    Hmac = hmac.HMAC(self.sourceKey, hashes.SHA256())
    Hmac2 = hmac.HMAC(self.sourceKey, hashes.SHA256())

    Hmac.update(b"mac")
    self.hashKey = Hmac.finalize()

    Hmac2.update(b"enc")
    self.encKey = Hmac2.finalize()

    if data is not None:
      self.kvs = pickle.loads(bytes.fromhex(data))





  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """

    return pickle.dumps(self.kvs).hex(), ''

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    if title in self.kvs:
      return self.kvs[title]
    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    else:
      note = note
    self.nonce += 1
    aesgcm = AESGCM(self.encKey)
    newTitle = hmac.HMAC(self.hashKey, hashes.SHA256())
    newTitle.update(title)
    good = newTitle.finalize()
    newNote = aesgcm.encrypt(self.nonce, note, title)
    self.kvs[good] = newNote


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    if title in self.kvs:
      del self.kvs[title]
      return True

    return False
