# Maintainer: devcoons <io.devcoons.com>
pkgname=jlock-encryption
pkgver=0.0.3
pkgrel=1
pkgdesc="A file encryption tool using AES encryption"
arch=('x86_64')
url="https://github.com/devcoons/jlock-encryption"
license=('GPL')
depends=('openssl') 
source=("jlock-encryption-0.0.3.tar.gz::https://github.com/devcoons/jlock-encryption/archive/refs/tags/v0.0.3.tar.gz")
sha256sums=('acc6cda07a05f949202a33c9da9997b28cb1c07874952b85139b3324abde7fc2')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  make
}

package() {
    cd "$srcdir/$pkgname-$pkgver"
    make PREFIX=/usr DESTDIR="$pkgdir" install
}