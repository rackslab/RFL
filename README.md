# RFL: Rackslab Foundation Library

## Description

RFL is a Python library and a set of common utilities useful to most
[Rackslab products](https://rackslab.io/en/solutions/).

RFL is actually a Python namespaces for multiples packages managed in this
single repository. The current packages are the following:

* `core`: Core library used by other packages.
* `authentication`: Manage authentication with LDAP and JWT tokens.
* `build`: Utilities to help backport builds of Python projects.
* `log`: Setup logger.
* `permissions`: Manage permissions with RBAC policy.
* `settings`: Manage configuration files settings.
* `web`: Predefined Flask application templates.

Each package has its own dedicated subdirectory in the `src` directory.

To avoid potential inconstencies between various packages, Git repository does
not contain `pyproject.toml` files in packages subdirectories. The files are
generated dynamically by a script with centrally managed information in
`packages.toml` file located in top-folder.

## Status

RFL is considered stable and ready for production.

## Install

To install a package from sources, run the following command:

```sh
$ pip install src/<package>
```

Where `<package>` is the name of a package (ex: `core`).

To install all packages at once, run this command:

```sh
$ ./install.sh
```

The packages can be installed in [_editable mode_]() by setting the
corresponding environment variable:

```sh
$ EDITABLE=1 ./install.sh
```

This is particularly usefull for using packages and modules in Python REPL.

## Tests

Run the following command to execute all unit tests:

```sh
$ ./test.sh
```

## Authors

RFL is developed and maintained by [Rackslab](https://rackslab.io). Please
[contact us](https://rackslab.io/en/contact/) for any questions or professionnal
services.

## License

RFL is distributed under the terms of the GNU General Public License v3.0
or later (GPLv3+).
