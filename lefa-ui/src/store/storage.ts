import storage from 'store2'

const WEB_TOKEN = 'WEB_TOKEN'

export const storages = {
  set setLocalStorageName(val: any) {
    if (!val) {
      storage.remove(WEB_TOKEN)
    } else {
      storage.set(WEB_TOKEN, val)
    }
  },
  get getLocalStorageName() {
    return storage.get(WEB_TOKEN)
  }
}
