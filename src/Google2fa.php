<?php

namespace Lifeonscreen\Google2fa;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Laravel\Nova\Tool;
use PragmaRX\Google2FA\Google2FA as G2fa;
use PragmaRX\Recovery\Recovery;
use Request;

class Google2fa extends Tool
{
    /**
     * Perform any tasks that need to happen when the tool is booted.
     *
     * @return void
     */
    public function boot()
    {
    }

    /**
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\Http\RedirectResponse|\Illuminate\View\View
     * @throws \PragmaRX\Google2FA\Exceptions\InsecureCallException
     */
    public function confirm()
    {
        if (app(Google2FAAuthenticator::class)->isAuthenticated()) {
            auth()->user()->user2fa->google2fa_enable = 1;
            auth()->user()->user2fa->save();

            return response()->redirectTo(config('nova.path'));
        }

        $data['google2fa_url'] = $this->getQrCodeUrl();
        $data['error'] = 'Secret is invalid.';

        return view('nova-google2fa::register', $data);
    }

    /**
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     * @throws \PragmaRX\Google2FA\Exceptions\InsecureCallException
     */
    public function register()
    {
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle(400),
                new SvgImageBackEnd()
            )
        );

        $data['google2fa_url'] = $this->getQrCodeUrl();

        return view('nova-google2fa::register', $data);
    }

    private function isRecoveryValid($recover, $recoveryHashes)
    {
        foreach ($recoveryHashes as $recoveryHash) {
            if (password_verify($recover, $recoveryHash)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return \Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Contracts\View\Factory|\Illuminate\Http\RedirectResponse|\Illuminate\Http\Response|\Illuminate\View\View
     */
    public function authenticate()
    {
        if ($recover = Request::get('recover')) {
            if ($this->isRecoveryValid($recover, json_decode(auth()->user()->user2fa->recovery, true)) === false) {
                $data['error'] = 'Recovery key is invalid.';

                return view('nova-google2fa::authenticate', $data);
            }

            $google2fa = new G2fa();
            $recovery = new Recovery();
            $secretKey = $google2fa->generateSecretKey();
            $data['recovery'] = $recovery
                ->setCount(config('lifeonscreen2fa.recovery_codes.count'))
                ->setBlocks(config('lifeonscreen2fa.recovery_codes.blocks'))
                ->setChars(config('lifeonscreen2fa.recovery_codes.chars_in_block'))
                ->toArray();

            $recoveryHashes = $data['recovery'];
            array_walk($recoveryHashes, function (&$value) {
                $value = password_hash($value, config('lifeonscreen2fa.recovery_codes.hashing_algorithm'));
            });

            $user2faModel = config('lifeonscreen2fa.models.user2fa');

            $user2faModel::where('user_id', auth()->user()->id)->delete();
            $user2fa = new $user2faModel();
            $user2fa->user_id = auth()->user()->id;
            $user2fa->google2fa_secret = $secretKey;
            $user2fa->recovery = json_encode($recoveryHashes);
            $user2fa->save();

            return response(view('nova-google2fa::recovery', $data));
        }

        if (app(Google2FAAuthenticator::class)->isAuthenticated()) {
            return response()->redirectTo(config('nova.path'));
        }

        $data['error'] = 'One time password is invalid.';

        return view('nova-google2fa::authenticate', $data);
    }

    protected function getQrCodeUrl()
    {
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle(400),
                new SvgImageBackEnd()
            )
        );

        return 'data:image/svg+xml;base64, ' . base64_encode(
                $writer->writeString((new G2fa)->getQRCodeUrl(
                    config('app.name'),
                    auth()->user()->email,
                    auth()->user()->user2fa->google2fa_secret
                ))
            );
    }
}
