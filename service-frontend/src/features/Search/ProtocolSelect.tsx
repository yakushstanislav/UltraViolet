import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Select, type SelectItem } from '@components/Select';

type ProtocolSelectProps = {
  defaultValue: string;
  name: string;
};

export function ProtocolSelect({ defaultValue, name }: ProtocolSelectProps) {
  const { t } = useTranslation();
  const [value, setValue] = useState(defaultValue);

  const options: SelectItem[] = [
    { value: '', label: t('searchPage.anyProtocol') },
    {
      label: t('searchPage.ogWeb'),
      options: [
        { value: 'http', label: t('searchPage.optHttp') },
        { value: 'https', label: t('searchPage.optHttps') },
      ],
    },
    {
      label: t('searchPage.ogRemote'),
      options: [
        { value: 'ssh', label: t('searchPage.optSsh') },
        { value: 'ftp', label: t('searchPage.optFtp') },
        { value: 'smtp', label: t('searchPage.optSmtp') },
      ],
    },
    {
      label: t('searchPage.ogDatabases'),
      options: [
        { value: 'postgresql', label: t('searchPage.optPostgresql') },
        { value: 'mysql', label: t('searchPage.optMysql') },
        { value: 'mongodb', label: t('searchPage.optMongodb') },
        { value: 'redis', label: t('searchPage.optRedis') },
        { value: 'memcached', label: t('searchPage.optMemcached') },
        { value: 'elasticsearch', label: t('searchPage.optElasticsearch') },
      ],
    },
    {
      label: t('searchPage.ogMessaging'),
      options: [
        { value: 'kafka', label: t('searchPage.optKafka') },
        { value: 'amqp', label: t('searchPage.optAmqp') },
      ],
    },
    {
      label: t('searchPage.ogOther'),
      options: [{ value: 'tcp', label: t('searchPage.optTcp') }],
    },
  ];

  return (
    <Select
      name={name}
      onChange={setValue}
      options={options}
      placeholder={t('searchPage.anyProtocol')}
      value={value}
    />
  );
}
