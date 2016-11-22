#include "formula.h"

int main(int argc, char *argv[]) {

    Formula *f = new Formula("(a && b) || c", 3);
    f->set_value(0, 1);
    //f->set_value(1, 1);

    cout << "RES " << f->eval() << "\n";

    return 0;
}
