package AppLib::CreateSelfSignedSSLCert;

use 5.010001;
use strict;
use warnings;
use Log::ger;

# AUTHORITY
# DATE
# DIST
# VERSION

use Expect;
#use File::chdir;
#use File::Temp;
use IPC::System::Options 'system', -log=>1;
use Proc::ChildError qw(explain_child_error);
use String::ShellQuote;

sub _sq { shell_quote($_[0]) }

our %SPEC;

$SPEC{create_self_signed_ssl_cert} = {
    v => 1.1,
    summary => 'Create self-signed SSL certificate',
    args => {
        hostname => {
            schema => ['str*' => match => qr/\A\w+(\.\w+)*\z/],
            req => 1,
            pos => 0,
        },
        ca => {
            summary => 'path to CA cert file',
            schema => ['str*'],
            'x.completion' => [filename => {file_regex_filter=>qr/\.(crt|pem)$/}],
        },
        ca_key => {
            summary => 'path to CA key file',
            schema => ['str*'],
            'x.completion' => [filename => {file_regex_filter=>qr/\.(key|pem)$/}],
        },
        interactive => {
            schema => [bool => default => 0],
            cmdline_aliases => {
                i => {},
            },
        },
        wildcard => {
            schema => [bool => default => 0],
            summary => 'If set to 1 then Common Name is set to *.hostname',
            description => 'Only when non-interactive',
        },
        csr_only => {
            schema => [bool => default => 0],
            summary => 'If set to 1 then will only generate .csr file',
            description => <<'_',

Can be useful if want to create .csr and submit it to a CA.

_
        },
    },
    deps => {
        exec => 'openssl',
    },
};
sub create_self_signed_ssl_cert {
    my %args = @_;

    my $h = $args{hostname};

    system("openssl genrsa 2048 > "._sq("$h.key"));
    return [500, "Can't generate key: ".explain_child_error()] if $?;
    chmod 0400, "$h.key" or warn "WARN: Can't chmod 400 $h.key: $!";

    my $cmd = "openssl req -new -key "._sq("$h.key")." -out "._sq("$h.csr");
    if ($args{interactive}) {
        system $cmd;
        return [500, "Can't generate csr: ".explain_child_error()] if $?;
    } else {
        my $exp = Expect->spawn($cmd);
        return [500, "Can't spawn openssl req"] unless $exp;
        $exp->expect(
            30,
            [ qr!^.+\[[^\]]*\]:!m ,=> sub {
                  my $exp = shift;
                  my $prompt = $exp->exp_match;
                  if ($prompt =~ /common name/i) {
                      $exp->send(($args{wildcard} ? "*." : "") . "$h\n");
                  } else {
                      $exp->send("\n");
                  }
                  exp_continue;
              } ],
        );
        $exp->soft_close;
    }
    if ($args{csr_only}) {
        log_info("Your CSR has been created at $h.csr");
        return [200];
    }

    # we can provide options later, but for now let's
    system(join(
        "",
        "openssl x509 -req -days 3650 -in ", _sq("$h.csr"),
        " -signkey ", _sq("$h.key"),
        ($args{ca} ? " -CA "._sq($args{ca}) : ""),
        ($args{ca_key} ? " -CAkey "._sq($args{ca_key}) : ""),
        ($args{ca} ? " -CAcreateserial" : ""),
        " -out ", _sq("$h.crt"),
    ));
    return [500, "Can't generate crt: ".explain_child_error()] if $?;

    system("openssl x509 -noout -fingerprint -text < "._sq("$h.crt").
               "> "._sq("$h.info"));
    return [500, "Can't generate info: ".explain_child_error()] if $?;

    system("cat "._sq("$h.crt")." "._sq("$h.key")." > "._sq("$h.pem"));
    return [500, "Can't generate pem: ".explain_child_error()] if $?;

    system("chmod 400 "._sq("$h.pem"));

    log_info("Your certificate has been created at $h.pem");

    [200];
}

$SPEC{create_ssl_csr} = {
    v => 1.1,
    args => {
        hostname => {
            schema => ['str*' => match => qr/\A\w+(\.\w+)*\z/],
            req => 1,
            pos => 0,
        },
        interactive => {
            schema => [bool => default => 0],
            cmdline_aliases => {
                i => {},
            },
        },
        wildcard => {
            schema => [bool => default => 0],
            summary => 'If set to 1 then Common Name is set to *.hostname',
            description => 'Only when non-interactive',
        },
    },
    deps => {
        # XXX should've depended on create_self_signed_ssl_cert() func instead,
        # and dependencies should be checked recursively.
        exec => 'openssl',
    },
};
sub create_ssl_csr {
    my %args = @_;
    create_self_signed_ssl_cert(%args, csr_only=>1);
}

1;
# ABSTRACT:

=head1 SYNOPSIS

=cut
