# broapt - An APT detection system based on Bro framework

<a rel="license" href="http://creativecommons.org/licenses/by-nc-nd/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-nd/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-nd/4.0/">Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License</a>.

## Synopsis

- `make docker`: build then run Docker environment (for testing)
- `make pipenv`: update pipenv on root directory
- `make download`: update then download Python dependency files into [`vendor/python/download`](vendor/python/download)
- `make submodule`: clone all submodules into [`vendor`](vendor)

## Licensing

This work is in general licensed under the [Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License](http://creativecommons.org/licenses/by-nc-nd/4.0/).
Part of this work is derived and copied from [Zeek](zeek/zeek) and [Broker](zeek/broker) both with [BSD 3-Clause License](LICENSE).
Original developed of this software and associated documentation files (the "Software") are hereby licensed under the
[Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License](COPYING.html).
No permits are foreordained unless granted by the author and maintainer of the Software, i.e. [Jarry Shaw](@jarryshaw).
