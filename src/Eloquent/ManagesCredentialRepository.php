<?php

namespace DarkGhostHunter\Larapass\Eloquent;

use Base64Url\Base64Url;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor as CredentialDescriptor;
use Webauthn\PublicKeyCredentialSource as CredentialSource;
use Webauthn\PublicKeyCredentialUserEntity as UserEntity;

trait ManagesCredentialRepository
{
    /**
     * Initializes the trait.
     *
     * @returns void
     */
    protected function initializeManagesCredentialRepository()
    {
        $this->mergeCasts([$this->getKeyName() => Casting\Base64UrlCast::class]);
    }

    /**
     * Finds a source of the credentials.
     *
     * @param  string  $binaryId
     *
     * @return null|\Webauthn\PublicKeyCredentialSource
     */
    public function findOneByCredentialId(string $binaryId): ?CredentialSource
    {
        return optional($this->find(Base64Url::encode($binaryId)))->toCredentialSource();
    }

    /**
     * Return an array of all credentials for a given user.
     *
     * @param  \Webauthn\PublicKeyCredentialUserEntity  $entity
     *
     * @return array|\Webauthn\PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(UserEntity $entity): array
    {
        return static::where('user_handle', $entity->id)->get()->map->toCredentialSource()->all();
    }

    /**
     * Update the credentials source into the storage.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     */
    public function saveCredentialSource(CredentialSource $source): void
    {
        // We will only update the credential counter only if it exists.
        static::where([$this->getKeyName() => Base64Url::encode($source->getPublicKeyCredentialId())])
            ->update(['counter' => $source->counter]);
    }

    /**
     * Creates a new Eloquent Model from a Credential Source.
     *
     * @param  \Webauthn\PublicKeyCredentialSource  $source
     *
     * @return self
     */
    public static function fromCredentialSource(CredentialSource $source)
    {
        return ($model = new static())->fill(
            [
                'user_handle' => $source->userHandle,
                'type' => $source->type,
                'transports' => $source->transports,
                'attestation_type' => $source->attestationType,
                'trust_path' => $source->trustPath->jsonSerialize(),
                'aaguid' => (string) $source->aaguid,
                'public_key' => $source->credentialPublicKey,
                'counter' => $source->counter,
                $model->getKeyName() => $source->publicKeyCredentialId,
            ]
        );
    }

    /**
     * Transform the current Eloquent model to a Credential Source.
     *
     * @return \Webauthn\PublicKeyCredentialSource
     */
    public function toCredentialSource(): CredentialSource
    {
        return new CredentialSource(
            $this->getKey(),
            $this->type,
            $this->transports->all(),
            $this->attestation_type,
            $this->trust_path,
            Uuid::fromString($this->aaguid->toString()),
            $this->public_key,
            $this->user_handle,
            $this->counter
        );
    }

    /**
     * Returns a Credential Descriptor (anything except the public key).
     *
     * @return \Webauthn\PublicKeyCredentialDescriptor
     */
    public function toCredentialDescriptor(): CredentialDescriptor
    {
        return $this->toCredentialSource()->getPublicKeyCredentialDescriptor();
    }
}
