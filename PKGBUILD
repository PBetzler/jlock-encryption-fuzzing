# Maintainer: devcoons <io.devcoons.com>
pkgname=jlock-encryption
pkgver=1.0.0 
pkgrel=1
pkgdesc="A file encryption tool using AES encryption"
arch=('x86_64')
url="https://github.com/devcoons/jlock-encryption"
license=('GPL')
depends=('openssl') 
source=("$pkgname-$pkgver.tar.gz::https://github.com/devcoons/jlock-encryption/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')  

build() {
  cd "$srcdir/$pkgname-$pkgver"
  make
}

package() {
    cd "$srcdir/$pkgname-$pkgver"
    make PREFIX=/usr DESTDIR="$pkgdir" install
}