<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class VerificationTokens extends Model
{
    protected $fillable = [
        'token',
        'otp',
        'verificationable_id',
        'verificationable_type',
        'verify_by',
    ];
    public function verifiable()
    {
        return $this->morphTo();
    }
}
