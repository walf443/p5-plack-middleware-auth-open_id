package Plack::Middleware::Auth::OpenID;

use strict;
use warnings;
use parent 'Plack::Middleware';
our $VERSION = '0.01';

use Net::OpenID::Consumer;
use LWPx::ParanoidAgent;
use Plack::Request;

sub call {
    my ($self, $env) = @_;

    my $session = $env->{'psgix.session'};
    unless ( $session->{$self->session_key} ) {
        $self->open_id_auth($env);
    }
    if ( $session->{ $self->session_key } ) {
        # success.
    }
}

sub open_id_auth {
    my ($self, $env) = @_;

    # TODO: don't use Plack::Request.
    my $req = Plack::Request->new($env);

    my $csr = Net::OpenID::Consumer->new(
        ua => LWPx::ParanoidAgent->new,
        args => $req,
        consumer_secret => sub { $_[0] },
    );

    if ( $req->param('open_id-check') ) {
        if ( my $setup_url = $csr->setup_url ) {
        } elsif ( $csr->user_cancel ) {
        } elsif ( my $identity = $csr->verified_identity ) {
            my $url = $identity->url;
            $env->{'psgix.session'}->{$self->session_key} = $url;
        }
    } else {
        my $trust_root = $req->uri->as_string;
        my $return_to = $req->uri->query_form(+{ $req->uri->query_form, 'open_id-check' => 1 })->as_string;
        my $identity = $csr->claimed_identity($self->auth_domain)
            or die $csr->err;

        my $check_url = $identity->check_url(return_to => $return_to, trust_root => $trust_root);
        return [ 302, [ Location => $check_url ], [] ];
    }
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::OpenID -

=head1 SYNOPSIS

  use Plack::Middleware::Auth::OpenID;

=head1 DESCRIPTION

Plack::Middleware::Auth::OpenID is

=head1 

It's just a idea. api may change in future and not work well.

=head1 AUTHOR

Keiji Yoshimi E<lt>walf443 at gmail dot comE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
