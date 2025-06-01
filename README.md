# Personal Blog

## Setup the environment

Install Ruby and other prerequisites:

```
sudo apt install ruby-full build-essential zlib1g-dev
```

set up a gem installation directory for your user account:

```
cat >> ~/.bashrc <<EOF
# Install Ruby Gems to ~/gems
export GEM_HOME="\$HOME/gems"
export PATH="\$HOME/gems/bin:\$PATH"
EOF
source ~/.bashrc
```

Finally, install Jekyll and Bundler:

```
gem install jekyll bundler
```

## Serve locally

```
$ git clone https://github.com/hrhirha/hrhirha.github.io.git blog
$ cd blog
$ bundle install
$ bundle exec jekyll serve
```

Browse to http://127.0.0.1:4000/